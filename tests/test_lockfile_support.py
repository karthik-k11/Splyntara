"""Tests for static uv and Poetry lockfile discovery and integration."""
from pathlib import Path

import pytest

from services.dependency_discovery import STATUS_PARTIAL, discover_dependencies
from services.sbom_generator import generate_sbom
from services.vulnerability_scanner import scan_vulnerabilities
from services import vulnerability_scanner
from services.security_dashboard import analyze_security_dashboard
from services.lockfile_parsers import parse_poetry_lock, parse_uv_lock
from services.manifest_parsers import parse_pyproject_toml

UV_LOCK = """
version = 1
requires-python = ">=3.10"

[[package]]
name = "Requests"
version = "2.32.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "urllib3", version = ">=1.26" }]

[[package]]
name = "urllib3"
version = "2.2.0"
source = { registry = "https://pypi.org/simple" }
"""

POETRY_LOCK = """
[[package]]
name = "Requests"
version = "2.32.0"
optional = false
python-versions = "*"
groups = ["main"]
source = { type = "legacy", url = "https://packages.example/simple" }
[package.dependencies]
urllib3 = ">=1.26"

[[package]]
name = "urllib3"
version = "2.2.0"
optional = false
python-versions = "*"
groups = ["main"]

[metadata]
lock-version = "2.0"
"""


def _write(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def _project(tmp_path: Path, lockfile: str, content: str) -> Path:
    project = tmp_path / "project"
    project.mkdir()
    _write(
        project / "pyproject.toml",
        """
[project]
name = "lockfile-demo"
dependencies = ["Requests>=2.0", "Flask>=3.0"]
""",
    )
    _write(project / lockfile, content)
    return project


def test_uv_lock_parser_normalizes_names_and_extracts_source_and_edges():
    result = parse_uv_lock(UV_LOCK)

    assert result["status"] == "parsed"
    assert [package["normalized_name"] for package in result["packages"]] == [
        "requests",
        "urllib3",
    ]
    assert result["packages"][0]["version"] == "2.32.0"
    assert result["packages"][0]["package_source"] == {
        "kind": "registry",
        "location": "https://pypi.org/simple",
    }
    assert result["packages"][0]["dependency_relationships"] == [
        {
            "name": "urllib3",
            "normalized_name": "urllib3",
            "version_constraint": ">=1.26",
        }
    ]


def test_poetry_lock_parser_extracts_multiple_packages_and_metadata():
    result = parse_poetry_lock(POETRY_LOCK)

    assert result["status"] == "parsed"
    assert [package["version"] for package in result["packages"]] == [
        "2.32.0",
        "2.2.0",
    ]
    assert result["packages"][0]["package_source"] == {
        "type": "legacy",
        "url": "https://packages.example/simple",
    }
    assert result["packages"][0]["lockfile_metadata"]["groups"] == ["main"]
    assert result["packages"][0]["dependency_relationships"][0][
        "normalized_name"
    ] == "urllib3"


@pytest.mark.parametrize(
    ("parser", "content"),
    [
        (parse_uv_lock, 'version = 1\nrevision = 3\nrequires-python = ">=3.12"\n'),
        (parse_poetry_lock, '[metadata]\nlock-version = "2.0"\n'),
    ],
)
def test_valid_empty_lockfiles_are_reported_without_resolutions(parser, content):
    result = parser(content)

    assert result["status"] == "empty"
    assert result["packages"] == []
    assert result["warnings"]


def test_poetry_pyproject_dependencies_preserve_direct_declarations():
    result = parse_pyproject_toml(
        """
[tool.poetry.dependencies]
python = "^3.12"
Requests = "^2.31"

[tool.poetry.group.dev.dependencies]
pytest = "^8.0"

[tool.poetry.group.dev]
optional = true
"""
    )

    dependencies = {item["normalized_name"]: item for item in result["dependencies"]}
    assert set(dependencies) == {"requests", "pytest"}
    assert dependencies["requests"]["version_constraint"] == "^2.31"
    assert dependencies["requests"]["dependency_type"] == "regular"
    assert dependencies["pytest"]["dependency_type"] == "optional"
    assert dependencies["pytest"]["optional_group"] == "dev"
    assert result["warnings"] == []


def test_uv_workspace_root_package_is_not_scanned_as_a_dependency(tmp_path):
    project = tmp_path / "workspace"
    project.mkdir()
    _write(
        project / "pyproject.toml",
        '[project]\nname = "workspace"\ndependencies = ["requests>=2.0"]\n',
    )
    _write(
        project / "uv.lock",
        """
version = 1
[[package]]
name = "workspace"
version = "0.1.0"
source = { editable = "." }
dependencies = [{ name = "requests", version = ">=2.0" }]

[[package]]
name = "requests"
version = "2.32.0"
""",
    )

    result = discover_dependencies(project)

    assert [item["normalized_name"] for item in result["inventory"]] == ["requests"]
    assert result["inventory"][0]["version"] == "2.32.0"


@pytest.mark.parametrize(
    ("lockfile", "content", "expected_status"),
    [
        ("uv.lock", "version = 1\n[[package]]\nname = [\n", "malformed"),
        ("poetry.lock", "", "empty"),
        ("uv.lock", "[[unsupported]]\nname = 'requests'\n", "unsupported"),
    ],
)
def test_invalid_or_empty_lockfiles_leave_dependencies_unresolved(
    tmp_path,
    lockfile,
    content,
    expected_status,
):
    project = _project(tmp_path, lockfile, content)

    result = discover_dependencies(project)

    assert result["status"] == STATUS_PARTIAL
    assert result["resolution"]["status"] == expected_status
    assert all(item["version"] is None for item in result["inventory"])
    assert any(lockfile in warning for warning in result["warnings"])


def test_missing_lockfile_is_reported_and_manifest_constraints_stay_unresolved(
    tmp_path,
):
    project = tmp_path / "project"
    project.mkdir()
    _write(project / "requirements.txt", "requests==2.31.0\n")

    result = discover_dependencies(project)

    assert result["status"] == STATUS_PARTIAL
    assert result["resolution"]["status"] == "missing"
    assert result["inventory"][0]["version"] is None
    assert result["inventory"][0]["version_constraints"] == ["==2.31.0"]
    assert any("No supported Python lockfile" in item for item in result["warnings"])


def test_both_supported_lockfiles_are_ambiguous_and_neither_is_merged(tmp_path):
    project = _project(tmp_path, "uv.lock", UV_LOCK)
    _write(project / "poetry.lock", POETRY_LOCK)

    result = discover_dependencies(project)

    assert result["status"] == STATUS_PARTIAL
    assert result["resolution"]["status"] == "ambiguous"
    assert [item["status"] for item in result["lockfiles"]] == [
        "ambiguous",
        "ambiguous",
    ]
    assert all(item["version"] is None for item in result["inventory"])
    assert {item["normalized_name"] for item in result["inventory"]} == {
        "flask",
        "requests",
    }
    assert any("neither lockfile was used" in item for item in result["warnings"])


@pytest.mark.parametrize(
    ("parser", "content"),
    [
        (parse_uv_lock, 'version = 99\n[[package]]\nname = "requests"\nversion = "2.0"\n'),
        (
            parse_poetry_lock,
            '[[package]]\nname = "requests"\nversion = "2.0"\n'
            '[metadata]\nlock-version = "9.0"\n',
        ),
    ],
)
def test_unknown_lockfile_schema_versions_are_not_used(parser, content):
    result = parser(content)

    assert result["status"] == "unsupported"
    assert result["packages"] == []
    assert result["warnings"]


class FakeOSVClient:
    def __init__(self):
        self.queries = None

    def query_batch(self, queries):
        self.queries = queries
        return [{"vulns": []} for _ in queries]

    def get_vulnerability(self, vulnerability_id):
        raise AssertionError(f"unexpected vulnerability detail request: {vulnerability_id}")


def test_lockfile_versions_flow_to_osv_and_sbom(tmp_path):
    project = _project(tmp_path, "uv.lock", UV_LOCK)
    client = FakeOSVClient()

    result = scan_vulnerabilities(project, client=client)

    assert result["total_dependencies_checked"] == 2
    assert client.queries == [
        {
            "package": {"name": "requests", "ecosystem": "PyPI"},
            "version": "2.32.0",
        },
        {
            "package": {"name": "urllib3", "ecosystem": "PyPI"},
            "version": "2.2.0",
        },
    ]

    sbom = generate_sbom(project)["sbom"]
    components = {component["name"].lower(): component for component in sbom["components"]}
    assert components["requests"]["version"] == "2.32.0"
    assert components["urllib3"]["version"] == "2.2.0"
    requests_ref = components["requests"]["bom-ref"]
    urllib3_ref = components["urllib3"]["bom-ref"]
    requests_dependencies = next(
        item for item in sbom["dependencies"] if item["ref"] == requests_ref
    )
    assert requests_dependencies["dependsOn"] == [urllib3_ref]
    request_properties = {
        (item["name"], item["value"])
        for item in components["requests"]["properties"]
    }
    assert ("splyntara:resolved_from", "uv.lock") in request_properties
    assert ("splyntara:dependency_classification", "direct") in request_properties


def test_dashboard_and_security_report_expose_resolution_coverage(
    tmp_path,
    client,
    monkeypatch,
):
    project = _project(tmp_path, "poetry.lock", POETRY_LOCK)
    osv = FakeOSVClient()
    monkeypatch.setattr(vulnerability_scanner, "OSVClient", lambda: osv)

    payload = analyze_security_dashboard(project, client=osv)

    assert payload["status"] == "partial"
    assert payload["project"]["resolution"]["status"] == "partial"
    assert payload["summary"]["resolved_dependencies"] == 2
    assert payload["summary"]["unresolved_dependencies"] == 1
    assert payload["summary"]["lockfile_status"] == "partial"
    assert payload["report"]["coverage"]["lockfile"] == "poetry.lock"
    assert payload["report"]["coverage"]["resolved_dependencies"] == 2
    assert payload["report"]["coverage"]["unresolved_dependencies"] == 1
    assert {item["dependency_classification"] for item in payload["dependencies"]} == {
        "direct",
        "transitive",
    }

    response = client.post(
        "/api/reports/security?format=html",
        json={"project_directory": str(project)},
    )
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "poetry.lock" in html
    assert "Resolved dependencies" in html
    assert "Coverage limitations" in html
    assert osv.queries is not None
