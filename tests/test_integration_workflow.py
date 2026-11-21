"""End-to-end integration tests for the Splyntara security workflow.

These tests drive the Flask API across dependency discovery, CycloneDX SBOM
generation, OSV scanning, risk analysis, dashboard analysis, report export, and
SBOM download. Every OSV request is served by a deterministic fake client, and
every project is created inside pytest's temporary directory.

Manifest discovery never resolves installed versions. Tests that exercise
resolved-version behavior therefore supply an explicit ``version`` on the same
real discovery result before patching the discovery boundary. Manifest-only
projects are always tested without that injection.
"""

import json
from copy import deepcopy
from pathlib import Path

import pytest
from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonValidator

import app as splyntara_app
from services import (
    dependency_discovery,
    risk_analyzer,
    sbom_generator,
    security_dashboard,
    vulnerability_scanner,
)
from services.osv_client import OSVTimeoutError

DISCOVERY_ENDPOINT = "/api/dependencies/discover"
SBOM_ENDPOINT = "/api/sbom/generate"
SBOM_DOWNLOAD_ENDPOINT = "/api/sbom/download"
SCAN_ENDPOINT = "/api/vulnerabilities/scan"
RISK_ENDPOINT = "/api/risks/analyze"
DASHBOARD_ENDPOINT = "/api/dashboard/analyze"
REPORT_ENDPOINT = "/api/reports/security"

RESOLVED_VERSIONS = {
    "flask": "3.0.3",
    "pytest": "8.2.0",
    "requests": "2.31.0",
    "urllib3": "2.2.1",
}

EXPECTED_QUERIES = [
    {"package": {"name": "flask", "ecosystem": "PyPI"}, "version": "3.0.3"},
    {"package": {"name": "pytest", "ecosystem": "PyPI"}, "version": "8.2.0"},
    {"package": {"name": "requests", "ecosystem": "PyPI"}, "version": "2.31.0"},
    {"package": {"name": "urllib3", "ecosystem": "PyPI"}, "version": "2.2.1"},
]


def _write(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def _write_standard_project(tmp_path: Path) -> Path:
    project = tmp_path / "integration-project"
    project.mkdir()

    _write(
        project / "requirements.txt",
        """
# Runtime dependencies
requests==2.31.0
Flask>=3.0
""".lstrip(),
    )
    _write(
        project / "pyproject.toml",
        """
[project]
name = "integration-demo"
dependencies = [
    "requests>=2.31.0",
    "urllib3==2.2.1",
]

[project.optional-dependencies]
dev = ["pytest>=8.0"]
""".lstrip(),
    )

    return project


def _resolved_discovery(project: Path, versions=None) -> dict:
    """Run real discovery using a temporary exact-version uv lockfile."""
    versions = versions or RESOLVED_VERSIONS
    lock_records = ["version = 1", ""]
    for package_name, version in sorted(versions.items()):
        lock_records.extend(
            [
                "[[package]]",
                f'name = "{package_name}"',
                f'version = "{version}"',
                "",
            ]
        )
    _write(project / "uv.lock", "\n".join(lock_records))
    result = dependency_discovery.discover_dependencies(project)
    assert result["status"] == "success"
    return result


def _patch_discovery(monkeypatch, discovery: dict) -> dict:
    """Make every API path consume the same resolved discovery snapshot."""
    snapshot = deepcopy(discovery)
    calls = {"count": 0}

    def fake_discover(_project_directory):
        calls["count"] += 1
        return deepcopy(snapshot)

    for module in (
        splyntara_app,
        sbom_generator,
        vulnerability_scanner,
        risk_analyzer,
        security_dashboard,
    ):
        monkeypatch.setattr(module, "discover_dependencies", fake_discover)

    return calls


class FakeOSVClient:
    def __init__(
        self,
        *,
        batch_results=None,
        details=None,
        batch_error=None,
        detail_errors=None,
    ):
        self.batch_results = batch_results or []
        self.details = details or {}
        self.batch_error = batch_error
        self.detail_errors = detail_errors or {}
        self.batch_calls = 0
        self.queries = []
        self.requested_ids = []

    def query_batch(self, queries):
        self.batch_calls += 1
        self.queries.append(deepcopy(queries))
        if self.batch_error is not None:
            raise self.batch_error
        return deepcopy(self.batch_results)

    def get_vulnerability(self, vulnerability_id):
        self.requested_ids.append(vulnerability_id)
        error = self.detail_errors.get(vulnerability_id)
        if error is not None:
            raise error
        return deepcopy(self.details[vulnerability_id])


@pytest.fixture
def fake_osv(monkeypatch):
    """Patch every scanner construction so no test can reach OSV over HTTP."""
    client = FakeOSVClient()
    monkeypatch.setattr(vulnerability_scanner, "OSVClient", lambda: client)
    return client


def _detail(
    vulnerability_id: str,
    package_name: str,
    severity: str,
    *,
    fixed: str = "9.9.9",
    summary: str | None = None,
) -> dict:
    return {
        "id": vulnerability_id,
        "summary": summary or f"Advisory for {package_name}",
        "details": "Detailed advisory text.",
        "aliases": [f"CVE-2026-{vulnerability_id[-4:]}"],
        "published": "2026-01-01T00:00:00Z",
        "modified": "2026-01-02T00:00:00Z",
        "severity": [{"type": "CVSS_V3", "score": "7.5"}],
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": package_name},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": fixed}],
                    }
                ],
            }
        ],
        "references": [
            {
                "type": "ADVISORY",
                "url": f"https://osv.dev/vulnerability/{vulnerability_id}",
            },
            {"type": "WEB", "url": "javascript:alert(1)"},
        ],
        "database_specific": {"severity": severity},
    }


def _configure_successful_osv(client: FakeOSVClient) -> None:
    client.batch_results = [
        {"vulns": []},
        {"vulns": []},
        {"vulns": [{"id": "GHSA-REQ-HIGH"}, {"id": "GHSA-REQ-MEDIUM"}]},
        {"vulns": [{"id": "GHSA-URLLIB3-CRIT"}]},
    ]
    client.details = {
        "GHSA-REQ-HIGH": _detail(
            "GHSA-REQ-HIGH",
            "requests",
            "HIGH",
            fixed="2.32.0",
            summary="High severity request parser issue",
        ),
        "GHSA-REQ-MEDIUM": _detail(
            "GHSA-REQ-MEDIUM",
            "requests",
            "MEDIUM",
            fixed="2.32.0",
            summary="Medium severity request handling issue",
        ),
        "GHSA-URLLIB3-CRIT": _detail(
            "GHSA-URLLIB3-CRIT",
            "urllib3",
            "CRITICAL",
            fixed="2.2.2",
            summary="Critical transport issue",
        ),
    }


def _validate_cyclonedx(document: dict) -> None:
    error = JsonValidator(SchemaVersion.V1_5).validate_str(json.dumps(document))
    assert error is None


def _comparable_report(report: dict) -> dict:
    """Drop only the point-in-time timestamp before comparing report snapshots."""
    return {key: value for key, value in report.items() if key != "generated_at"}


def test_successful_project_workflow_remains_consistent(
    client,
    tmp_path,
    monkeypatch,
    fake_osv,
):
    project = _write_standard_project(tmp_path)
    discovery = _resolved_discovery(project)
    discovery_calls = _patch_discovery(monkeypatch, discovery)
    _configure_successful_osv(fake_osv)

    # 1. Discovery reads both manifests and exposes a normalized inventory.
    discovery_response = client.post(
        DISCOVERY_ENDPOINT,
        json={"project_directory": str(project)},
    )
    assert discovery_response.status_code == 200
    discovered = discovery_response.get_json()
    assert discovered["status"] == "success"
    assert [item["filename"] for item in discovered["manifests"]] == [
        "requirements.txt",
        "pyproject.toml",
    ]

    inventory = {
        entry["normalized_name"]: entry for entry in discovered["inventory"]
    }
    assert set(inventory) == {"flask", "pytest", "requests", "urllib3"}
    assert inventory["requests"]["version"] == "2.31.0"
    assert inventory["requests"]["version_constraints"] == [
        "==2.31.0",
        ">=2.31.0",
    ]
    assert inventory["requests"]["source_manifests"] == [
        "pyproject.toml",
        "requirements.txt",
    ]
    assert inventory["pytest"]["dependency_types"] == ["optional"]
    assert fake_osv.batch_calls == 0

    # 2. SBOM generation uses the same resolved inventory and remains valid
    # CycloneDX 1.5 JSON.
    sbom_response = client.post(
        SBOM_ENDPOINT,
        json={"project_directory": str(project)},
    )
    assert sbom_response.status_code == 200
    sbom = sbom_response.get_json()
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.5"
    assert sbom["metadata"]["component"]["name"] == project.name
    assert [component["purl"] for component in sbom["components"]] == [
        "pkg:pypi/flask@3.0.3",
        "pkg:pypi/pytest@8.2.0",
        "pkg:pypi/requests@2.31.0",
        "pkg:pypi/urllib3@2.2.1",
    ]
    requests_component = next(
        component
        for component in sbom["components"]
        if component["purl"] == "pkg:pypi/requests@2.31.0"
    )
    request_properties = {
        (item["name"], item["value"])
        for item in requests_component["properties"]
    }
    assert ("splyntara:version_constraint", "==2.31.0") in request_properties
    assert ("splyntara:version_constraint", ">=2.31.0") in request_properties
    _validate_cyclonedx(sbom)
    assert fake_osv.batch_calls == 0

    # 3. One OSV batch scan checks all four resolved dependencies.
    scan_response = client.post(
        SCAN_ENDPOINT,
        json={"project_directory": str(project)},
    )
    assert scan_response.status_code == 200
    scan = scan_response.get_json()
    assert scan["status"] == "success"
    assert scan["total_dependencies_checked"] == 4
    assert scan["eligible_dependency_count"] == 4
    assert scan["unresolved_dependency_count"] == 0
    assert scan["vulnerable_dependency_count"] == 2
    assert scan["total_vulnerability_count"] == 3
    assert {finding["vulnerability_id"] for finding in scan["vulnerabilities"]} == {
        "GHSA-REQ-HIGH",
        "GHSA-REQ-MEDIUM",
        "GHSA-URLLIB3-CRIT",
    }
    assert fake_osv.batch_calls == 1
    assert fake_osv.queries[-1] == EXPECTED_QUERIES

    # 4. Risk analysis reuses that scan contract and classifies the highest
    # severity per dependency.
    risk_response = client.post(
        RISK_ENDPOINT,
        json={"project_directory": str(project)},
    )
    assert risk_response.status_code == 200
    risk = risk_response.get_json()
    assert risk["status"] == "success"
    assert risk["project_risk"] == "Critical"
    assert risk["risk_counts"] == {
        "Critical": 1,
        "High": 1,
        "Medium": 0,
        "Low": 2,
        "Unknown": 0,
    }
    assert risk["summary"]["scan_coverage"] == "complete"
    risk_dependencies = {
        entry["package_name"]: entry for entry in risk["dependencies"]
    }
    assert risk_dependencies["requests"]["risk_classification"] == "High"
    assert risk_dependencies["requests"]["vulnerability_count"] == 2
    assert risk_dependencies["requests"]["vulnerability_ids"] == [
        "GHSA-REQ-HIGH",
        "GHSA-REQ-MEDIUM",
    ]
    assert risk_dependencies["urllib3"]["risk_classification"] == "Critical"
    assert risk_dependencies["flask"]["risk_classification"] == "Low"
    assert risk_dependencies["pytest"]["risk_classification"] == "Low"

    # 5. A dashboard analysis performs exactly one OSV scan, not one per
    # dependency and not a second scan during risk analysis.
    batch_calls_before_dashboard = fake_osv.batch_calls
    detail_calls_before_dashboard = len(fake_osv.requested_ids)
    discovery_calls_before_dashboard = discovery_calls["count"]
    dashboard_response = client.post(
        DASHBOARD_ENDPOINT,
        json={"project_directory": str(project)},
    )
    assert dashboard_response.status_code == 200
    dashboard = dashboard_response.get_json()
    assert dashboard["status"] == "success"
    assert dashboard["project"]["name"] == project.name
    assert (
        dashboard["summary"]["total_dependencies"]
        == risk["summary"]["total_dependencies"]
    )
    assert dashboard["summary"]["risk_counts"] == risk["summary"]["risk_counts"]
    assert (
        dashboard["summary"]["vulnerable_dependencies"]
        == risk["summary"]["vulnerable_dependency_count"]
    )
    assert (
        dashboard["summary"]["unresolved_dependencies"]
        == risk["summary"]["unresolved_dependency_count"]
    )
    assert (
        dashboard["summary"]["incomplete_coverage_dependencies"]
        == risk["summary"]["incomplete_coverage_dependency_count"]
    )
    assert (
        dashboard["summary"]["project_risk"]
        == risk["summary"]["project_risk"]
    )
    assert (
        dashboard["summary"]["scan_coverage"]
        == risk["summary"]["scan_coverage"]
    )
    assert dashboard["risk"]["dependencies"] == risk["dependencies"]
    assert dashboard["warnings"] == []
    assert dashboard["errors"] == []

    assert fake_osv.batch_calls == batch_calls_before_dashboard + 1
    dashboard_detail_calls = fake_osv.requested_ids[detail_calls_before_dashboard:]
    assert dashboard_detail_calls == [
        "GHSA-REQ-HIGH",
        "GHSA-REQ-MEDIUM",
        "GHSA-URLLIB3-CRIT",
    ]
    assert len(dashboard_detail_calls) == len(set(dashboard_detail_calls))
    assert discovery_calls["count"] == discovery_calls_before_dashboard + 1

    report = dashboard["report"]
    assert report["format"] == "splyntara.security-report"
    assert report["version"] == 1
    assert report["scan_summary"] == dashboard["summary"]
    assert report["project"]["name"] == project.name
    assert [item["filename"] for item in report["project"]["manifests"]] == [
        "requirements.txt",
        "pyproject.toml",
    ]

    report_inventory = {
        entry["package_name"]: entry for entry in report["inventory"]
    }
    assert set(report_inventory) == {"flask", "pytest", "requests", "urllib3"}
    for dependency in dashboard["dependencies"]:
        package_name = dependency["package_name"]
        report_entry = report_inventory[package_name]
        assert report_entry["resolved_version"] == dependency["resolved_version"]
        assert report_entry["risk"] == dependency["risk_classification"]
        assert (
            report_entry["vulnerability_count"]
            == dependency["vulnerability_count"]
        )
        assert (
            report_entry["manifest_sources"]
            == dependency["manifest_sources"]
        )

    assert {
        finding["vulnerability_id"] for finding in report["vulnerabilities"]
    } == {"GHSA-REQ-HIGH", "GHSA-REQ-MEDIUM", "GHSA-URLLIB3-CRIT"}
    assert report["coverage"]["status"] == "complete"
    assert report["coverage"]["dependencies_checked"] == 4
    assert report["generated_at"] in dashboard["report_html"]
    assert "GHSA-URLLIB3-CRIT" in dashboard["report_html"]
    assert "Critical" in dashboard["report_html"]

    # 6. JSON export is the same analysis snapshot shape as the dashboard
    # report. Only the generation timestamp may differ between requests.
    batch_calls_before_report = fake_osv.batch_calls
    discovery_calls_before_report = discovery_calls["count"]
    report_response = client.post(
        REPORT_ENDPOINT,
        json={"project_directory": str(project)},
    )
    assert report_response.status_code == 200
    assert report_response.mimetype == "application/json"
    assert report_response.headers["Content-Disposition"].startswith("attachment;")
    exported_report = json.loads(report_response.get_data(as_text=True))
    assert _comparable_report(exported_report) == _comparable_report(report)
    assert fake_osv.batch_calls == batch_calls_before_report + 1
    assert discovery_calls["count"] == discovery_calls_before_report + 1

    # 7. HTML export is a downloadable standalone report with the same
    # findings and project identity.
    batch_calls_before_html = fake_osv.batch_calls
    html_response = client.post(
        REPORT_ENDPOINT + "?format=html",
        json={"project_directory": str(project)},
    )
    assert html_response.status_code == 200
    assert html_response.mimetype == "text/html"
    assert html_response.headers["Content-Disposition"].startswith("attachment;")
    html = html_response.get_data(as_text=True)
    assert "<!doctype html>" in html
    assert "Dependency security assessment" in html
    assert project.name in html
    assert "GHSA-REQ-HIGH" in html
    assert "GHSA-URLLIB3-CRIT" in html
    assert "Critical" in html
    assert "javascript:alert(1)" not in html
    assert fake_osv.batch_calls == batch_calls_before_html + 1

    # 8. SBOM download uses the same dependency inventory without invoking OSV.
    batch_calls_before_download = fake_osv.batch_calls
    download_response = client.post(
        SBOM_DOWNLOAD_ENDPOINT,
        json={"project_directory": str(project)},
    )
    assert download_response.status_code == 200
    assert download_response.mimetype == "application/json"
    assert download_response.headers["Content-Disposition"].endswith(
        '-sbom.json"'
    )
    downloaded_sbom = json.loads(download_response.get_data(as_text=True))
    assert downloaded_sbom["specVersion"] == sbom["specVersion"]
    assert downloaded_sbom["metadata"]["component"]["name"] == project.name
    assert [component["purl"] for component in downloaded_sbom["components"]] == [
        component["purl"] for component in sbom["components"]
    ]
    _validate_cyclonedx(downloaded_sbom)
    assert fake_osv.batch_calls == batch_calls_before_download


def test_manifest_pins_without_resolved_versions_are_never_reported_safe(
    client,
    tmp_path,
    fake_osv,
):
    project = _write_standard_project(tmp_path)

    discovery_response = client.post(
        DISCOVERY_ENDPOINT,
        json={"project_directory": str(project)},
    )
    assert discovery_response.status_code == 200
    discovered = discovery_response.get_json()
    assert discovered["status"] == "partial"
    assert len(discovered["inventory"]) == 4
    for entry in discovered["inventory"]:
        assert entry["version"] is None
        assert entry["version_constraints"]

    sbom_response = client.post(
        SBOM_DOWNLOAD_ENDPOINT,
        json={"project_directory": str(project)},
    )
    assert sbom_response.status_code == 200
    sbom = json.loads(sbom_response.get_data(as_text=True))
    assert [component["purl"] for component in sbom["components"]] == [
        "pkg:pypi/flask",
        "pkg:pypi/pytest",
        "pkg:pypi/requests",
        "pkg:pypi/urllib3",
    ]
    assert all("version" not in component for component in sbom["components"])
    _validate_cyclonedx(sbom)

    scan_response = client.post(
        SCAN_ENDPOINT,
        json={"project_directory": str(project)},
    )
    assert scan_response.status_code == 200
    scan = scan_response.get_json()
    assert scan["status"] == "partial"
    assert scan["total_dependencies_checked"] == 0
    assert scan["eligible_dependency_count"] == 0
    assert scan["unresolved_dependency_count"] == 4
    assert scan["vulnerabilities"] == []
    assert any("no resolved version" in warning for warning in scan["warnings"])
    assert fake_osv.batch_calls == 0

    risk_response = client.post(
        RISK_ENDPOINT,
        json={"project_directory": str(project)},
    )
    assert risk_response.status_code == 200
    risk = risk_response.get_json()
    assert risk["status"] == "partial"
    assert risk["project_risk"] == "Unknown"
    assert risk["risk_counts"] == {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Unknown": 4,
    }
    assert risk["summary"]["unresolved_dependency_count"] == 4
    assert risk["scan_coverage"] == "unavailable"
    for dependency in risk["dependencies"]:
        assert dependency["version_resolved"] is False
        assert dependency["resolved_version"] is None
        assert dependency["risk_classification"] == "Unknown"
        assert dependency["scan_coverage"] == "unresolved"
        assert dependency["vulnerability_count"] == 0
    assert fake_osv.batch_calls == 0

    dashboard_response = client.post(
        DASHBOARD_ENDPOINT,
        json={"project_directory": str(project)},
    )
    assert dashboard_response.status_code == 200
    dashboard = dashboard_response.get_json()
    assert dashboard["status"] == "partial"
    assert dashboard["summary"]["project_risk"] == "Unknown"
    assert dashboard["summary"]["unknown_risk_dependencies"] == 4
    assert dashboard["summary"]["unresolved_dependencies"] == 4
    assert dashboard["summary"]["scan_coverage"] == "unavailable"
    assert dashboard["summary"]["risk_counts"]["Low"] == 0

    report = dashboard["report"]
    assert report["summary"]["project_risk"] == "Unknown"
    assert report["summary"]["risk_counts"]["Low"] == 0
    assert report["coverage"]["status"] == "unavailable"
    assert report["coverage"]["unresolved_dependencies"] == 4
    for entry in report["inventory"]:
        assert entry["resolved_version"] is None
        assert entry["version_resolved"] is False
        assert entry["risk"] == "Unknown"
    for entry in report["risk"]["dependencies"]:
        assert entry["risk"] == "Unknown"
        assert entry["scan_coverage"] == "unresolved"
    assert any(
        "excluded from OSV scanning" in note
        for note in report["coverage"]["notes"]
    )
    assert "Unresolved" in dashboard["report_html"]
    assert "Unknown" in dashboard["report_html"]
    assert fake_osv.batch_calls == 0


def test_project_with_no_manifests_is_empty_across_workflow(
    client,
    tmp_path,
    fake_osv,
):
    project = tmp_path / "empty-project"
    project.mkdir()
    _write(project / "package.json", "{}")

    discovery_response = client.post(
        DISCOVERY_ENDPOINT,
        json={"project_directory": str(project)},
    )
    assert discovery_response.status_code == 200
    discovered = discovery_response.get_json()
    assert discovered["status"] == "no_manifests"
    assert discovered["manifests"] == []
    assert discovered["inventory"] == []

    sbom_response = client.post(
        SBOM_DOWNLOAD_ENDPOINT,
        json={"project_directory": str(project)},
    )
    assert sbom_response.status_code == 200
    sbom = json.loads(sbom_response.get_data(as_text=True))
    assert sbom.get("components", []) == []
    _validate_cyclonedx(sbom)

    dashboard_response = client.post(
        DASHBOARD_ENDPOINT,
        json={"project_directory": str(project)},
    )
    assert dashboard_response.status_code == 200
    dashboard = dashboard_response.get_json()
    assert dashboard["status"] == "empty"
    assert dashboard["summary"]["total_dependencies"] == 0
    assert dashboard["summary"]["scan_coverage"] == "empty"
    assert dashboard["summary"]["project_risk"] == "Unknown"
    assert dashboard["dependencies"] == []
    assert dashboard["vulnerabilities"] == []
    assert dashboard["report"]["inventory"] == []
    assert dashboard["report"]["coverage"]["status"] == "empty"
    assert any(
        "No Python manifests" in note
        for note in dashboard["report"]["coverage"]["notes"]
    )
    assert fake_osv.batch_calls == 0


def test_empty_manifest_inventory_is_not_treated_as_scanned(
    client,
    tmp_path,
    fake_osv,
):
    project = tmp_path / "empty-inventory"
    project.mkdir()
    _write(project / "requirements.txt", "# no dependencies\n")

    discovery_response = client.post(
        DISCOVERY_ENDPOINT,
        json={"project_directory": str(project)},
    )
    assert discovery_response.status_code == 200
    discovered = discovery_response.get_json()
    assert discovered["status"] == "partial"
    assert discovered["unique_dependency_count"] == 0
    assert discovered["inventory"] == []
    assert discovered["manifests"][0]["status"] == "parsed"

    scan_response = client.post(
        SCAN_ENDPOINT,
        json={"project_directory": str(project)},
    )
    assert scan_response.status_code == 200
    scan = scan_response.get_json()
    assert scan["status"] == "empty"
    assert scan["inventory_count"] == 0
    assert scan["total_dependencies_checked"] == 0
    assert scan["unresolved_dependency_count"] == 0

    dashboard_response = client.post(
        DASHBOARD_ENDPOINT,
        json={"project_directory": str(project)},
    )
    assert dashboard_response.status_code == 200
    dashboard = dashboard_response.get_json()
    assert dashboard["status"] == "empty"
    assert dashboard["summary"]["total_dependencies"] == 0
    assert dashboard["summary"]["scan_coverage"] == "empty"
    assert dashboard["report"]["coverage"]["status"] == "empty"
    assert any(
        "No Python manifests or dependency declarations" in note
        for note in dashboard["report"]["coverage"]["notes"]
    )
    assert fake_osv.batch_calls == 0


def test_malformed_manifests_flow_through_discovery_sbom_and_dashboard(
    client,
    tmp_path,
    fake_osv,
):
    project = tmp_path / "malformed-project"
    project.mkdir()
    _write(project / "requirements.txt", "requests>=2.0\nnot valid!!\n")
    _write(project / "pyproject.toml", "[project\ndependencies = [\n")

    discovery_response = client.post(
        DISCOVERY_ENDPOINT,
        json={"project_directory": str(project)},
    )
    assert discovery_response.status_code == 200
    discovered = discovery_response.get_json()
    assert discovered["status"] == "partial"
    assert [entry["normalized_name"] for entry in discovered["inventory"]] == [
        "requests"
    ]
    assert any("malformed TOML" in warning for warning in discovered["warnings"])
    assert any(
        "could not parse dependency declaration" in warning
        for warning in discovered["warnings"]
    )

    sbom_response = client.post(
        SBOM_DOWNLOAD_ENDPOINT,
        json={"project_directory": str(project)},
    )
    assert sbom_response.status_code == 200
    sbom = json.loads(sbom_response.get_data(as_text=True))
    assert [component["purl"] for component in sbom["components"]] == [
        "pkg:pypi/requests"
    ]
    warning_properties = [
        item["value"]
        for item in sbom["metadata"]["properties"]
        if item["name"] == "splyntara:warning"
    ]
    assert any("malformed TOML" in warning for warning in warning_properties)
    assert any(
        "could not parse dependency declaration" in warning
        for warning in warning_properties
    )
    _validate_cyclonedx(sbom)

    dashboard_response = client.post(
        DASHBOARD_ENDPOINT,
        json={"project_directory": str(project)},
    )
    assert dashboard_response.status_code == 200
    dashboard = dashboard_response.get_json()
    assert dashboard["status"] == "partial"
    assert dashboard["summary"]["total_dependencies"] == 1
    assert dashboard["summary"]["unresolved_dependencies"] == 1
    assert dashboard["summary"]["project_risk"] == "Unknown"
    assert dashboard["dependencies"][0]["risk_classification"] == "Unknown"
    assert any("malformed TOML" in warning for warning in dashboard["warnings"])
    assert any(
        "could not parse dependency declaration" in warning
        for warning in dashboard["warnings"]
    )
    assert any(
        "malformed TOML" in warning for warning in dashboard["report"]["warnings"]
    )
    assert fake_osv.batch_calls == 0


def test_partial_osv_detail_failure_preserves_known_findings_and_unknowns(
    client,
    tmp_path,
    monkeypatch,
    fake_osv,
):
    project = tmp_path / "partial-osv-project"
    project.mkdir()
    _write(project / "requirements.txt", "flask>=3.0\nrequests>=2.31.0\n")
    discovery = _resolved_discovery(
        project,
        {"flask": "3.0.3", "requests": "2.31.0"},
    )
    _patch_discovery(monkeypatch, discovery)

    fake_osv.batch_results = [
        {"vulns": [{"id": "GHSA-FAIL"}]},
        {"vulns": [{"id": "GHSA-OK"}]},
    ]
    fake_osv.details = {
        "GHSA-OK": _detail(
            "GHSA-OK",
            "requests",
            "CRITICAL",
            fixed="2.32.0",
        )
    }
    fake_osv.detail_errors = {
        "GHSA-FAIL": OSVTimeoutError("detail timed out")
    }

    dashboard_response = client.post(
        DASHBOARD_ENDPOINT,
        json={"project_directory": str(project)},
    )
    assert dashboard_response.status_code == 200
    dashboard = dashboard_response.get_json()
    assert dashboard["status"] == "partial"
    assert dashboard["summary"]["total_dependencies"] == 2
    assert dashboard["summary"]["vulnerable_dependencies"] == 1
    assert dashboard["summary"]["total_vulnerabilities"] == 1
    assert dashboard["summary"]["risk_counts"] == {
        "Critical": 1,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Unknown": 1,
    }
    assert dashboard["summary"]["project_risk"] == "Critical"
    assert dashboard["summary"]["scan_coverage"] == "partial"
    assert dashboard["summary"]["incomplete_coverage_dependencies"] == 2
    assert dashboard["summary"]["unresolved_dependencies"] == 0
    assert any("detail timed out" in error for error in dashboard["errors"])

    dependencies = {
        entry["package_name"]: entry for entry in dashboard["dependencies"]
    }
    assert dependencies["flask"]["risk_classification"] == "Unknown"
    assert dependencies["flask"]["scan_coverage"] == "partial"
    assert dependencies["flask"]["vulnerability_count"] == 0
    assert dependencies["requests"]["risk_classification"] == "Critical"
    assert dependencies["requests"]["scan_coverage"] == "partial"
    assert dependencies["requests"]["vulnerability_count"] == 1

    report = dashboard["report"]
    assert report["coverage"]["status"] == "partial"
    assert report["coverage"]["incomplete_coverage_dependencies"] == 2
    assert any("detail timed out" in error for error in report["errors"])
    assert any(
        "did not receive complete OSV coverage" in note
        for note in report["coverage"]["notes"]
    )
    assert "GHSA-OK" in dashboard["report_html"]
    assert "Unknown" in dashboard["report_html"]
    assert fake_osv.batch_calls == 1


def test_osv_batch_timeout_is_reported_as_unknown_in_dashboard_and_report(
    client,
    tmp_path,
    monkeypatch,
    fake_osv,
):
    project = tmp_path / "timeout-project"
    project.mkdir()
    _write(project / "requirements.txt", "flask>=3.0\nrequests>=2.31.0\n")
    discovery = _resolved_discovery(
        project,
        {"flask": "3.0.3", "requests": "2.31.0"},
    )
    _patch_discovery(monkeypatch, discovery)
    fake_osv.batch_error = OSVTimeoutError("OSV request timed out")

    dashboard_response = client.post(
        DASHBOARD_ENDPOINT,
        json={"project_directory": str(project)},
    )
    assert dashboard_response.status_code == 200
    dashboard = dashboard_response.get_json()
    assert dashboard["status"] == "partial"
    assert dashboard["summary"]["total_dependencies"] == 2
    assert dashboard["summary"]["project_risk"] == "Unknown"
    assert dashboard["summary"]["risk_counts"]["Unknown"] == 2
    assert dashboard["summary"]["scan_coverage"] == "unavailable"
    assert dashboard["summary"]["incomplete_coverage_dependencies"] == 2
    assert dashboard["summary"]["dependencies_checked"] == 0
    assert all(
        dependency["risk_classification"] == "Unknown"
        for dependency in dashboard["dependencies"]
    )
    assert any("timed out" in error for error in dashboard["errors"])

    report = dashboard["report"]
    assert report["coverage"]["status"] == "unavailable"
    assert report["summary"]["risk_counts"]["Low"] == 0
    assert any("timed out" in error for error in report["errors"])
    assert "Errors" in dashboard["report_html"]
    assert fake_osv.batch_calls == 1

    report_response = client.post(
        REPORT_ENDPOINT,
        json={"project_directory": str(project)},
    )
    assert report_response.status_code == 200
    exported = json.loads(report_response.get_data(as_text=True))
    assert exported["coverage"]["status"] == "unavailable"
    assert exported["summary"]["project_risk"] == "Unknown"
    assert any("timed out" in error for error in exported["errors"])
    assert fake_osv.batch_calls == 2


@pytest.mark.parametrize(
    "endpoint",
    [
        DISCOVERY_ENDPOINT,
        SBOM_ENDPOINT,
        SBOM_DOWNLOAD_ENDPOINT,
        SCAN_ENDPOINT,
        RISK_ENDPOINT,
        DASHBOARD_ENDPOINT,
        REPORT_ENDPOINT,
    ],
)
def test_missing_project_directory_is_rejected_without_osv(
    client,
    tmp_path,
    fake_osv,
    endpoint,
):
    missing = tmp_path / "does-not-exist"

    response = client.post(
        endpoint,
        json={"project_directory": str(missing)},
    )

    assert response.status_code == 400
    payload = response.get_json()
    assert payload["status"] == "error"
    assert "could not access project directory" in payload["error"]
    assert fake_osv.batch_calls == 0


def test_file_path_and_inaccessible_path_are_rejected_without_osv(
    client,
    tmp_path,
    fake_osv,
):
    file_path = tmp_path / "requirements.txt"
    _write(file_path, "flask>=3.0\n")

    file_response = client.post(
        DASHBOARD_ENDPOINT,
        json={"project_directory": str(file_path)},
    )
    assert file_response.status_code == 400
    assert "is not a directory" in file_response.get_json()["error"]

    blocking_file = tmp_path / "blocking-parent"
    _write(blocking_file, "not a directory")
    inaccessible = blocking_file / "project"

    inaccessible_response = client.post(
        DASHBOARD_ENDPOINT,
        json={"project_directory": str(inaccessible)},
    )
    assert inaccessible_response.status_code == 400
    assert "could not access project directory" in (
        inaccessible_response.get_json()["error"]
    )
    assert fake_osv.batch_calls == 0


def test_sbom_serialization_error_is_returned_as_a_clean_export_error(
    client,
    tmp_path,
    monkeypatch,
    fake_osv,
):
    project = tmp_path / "sbom-error-project"
    project.mkdir()
    _write(project / "requirements.txt", "flask>=3.0\n")

    def fail_outputter(*_args, **_kwargs):
        raise RuntimeError("serializer exploded")

    monkeypatch.setattr(sbom_generator, "make_outputter", fail_outputter)

    response = client.post(
        SBOM_DOWNLOAD_ENDPOINT,
        json={"project_directory": str(project)},
    )

    assert response.status_code == 400
    payload = response.get_json()
    assert payload["status"] == "error"
    assert payload["sbom"] is None
    assert payload["error"] == "could not generate SBOM"
    assert "serializer exploded" not in payload["error"]
    assert all("serializer exploded" not in warning for warning in payload["warnings"])
    assert fake_osv.batch_calls == 0


def test_report_export_validation_errors_do_not_start_an_analysis(
    client,
    tmp_path,
    fake_osv,
):
    _write(tmp_path / "requirements.txt", "flask>=3.0\n")

    missing_response = client.post(REPORT_ENDPOINT, json={})
    assert missing_response.status_code == 400
    assert missing_response.get_json()["error"] == "project_directory is required"
    assert missing_response.get_json()["report"] is None

    format_response = client.post(
        REPORT_ENDPOINT + "?format=xml",
        json={"project_directory": str(tmp_path)},
    )
    assert format_response.status_code == 400
    assert format_response.get_json()["error"] == (
        "format must be 'json' or 'html'"
    )
    assert format_response.get_json()["report"] is None
    assert fake_osv.batch_calls == 0
