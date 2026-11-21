"""Tests for the dependency discovery engine and manifest registry."""

import os
from pathlib import Path

import pytest

from services import dependency_discovery
from services.dependency_discovery import (
    FORMAT_PYPROJECT,
    FORMAT_REQUIREMENTS,
    STATUS_ERROR,
    STATUS_NO_MANIFESTS,
    STATUS_PARTIAL,
    STATUS_SUCCESS,
    _is_within_directory,
    detect_manifests,
    discover_dependencies,
    discover_project,
    scan_project,
)
from services.manifest_parsers import MANIFEST_PARSERS


def _write(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def test_manifest_registry_contains_supported_formats():
    assert set(MANIFEST_PARSERS) == {"requirements.txt", "pyproject.toml"}


def test_detect_manifests_reports_path_and_format(tmp_path):
    requirements = tmp_path / "requirements.txt"
    _write(requirements, "requests\n")

    manifests = detect_manifests(tmp_path)

    assert manifests == [
        {
            "filename": "requirements.txt",
            "format": FORMAT_REQUIREMENTS,
            "path": requirements,
        }
    ]


def test_detect_manifests_ignores_unsupported_and_nested_manifests(tmp_path):
    _write(tmp_path / "package.json", "{}")
    nested = tmp_path / "nested"
    nested.mkdir()
    _write(nested / "requirements.txt", "requests\n")

    assert detect_manifests(tmp_path) == []


def test_detect_manifests_returns_empty_list_for_empty_directory(tmp_path):
    assert detect_manifests(tmp_path) == []


def test_discovery_accepts_absolute_directory_paths_with_spaces_and_explorer_quotes(
    tmp_path,
):
    project = tmp_path / "NMIMS VoiceAgent project"
    project.mkdir()

    unquoted = discover_dependencies(str(project))
    quoted = discover_dependencies(f'"{project}"')

    assert Path(str(project)).is_absolute()
    assert unquoted["status"] == STATUS_NO_MANIFESTS
    assert quoted["status"] == STATUS_NO_MANIFESTS
    assert quoted["project_directory"] == str(project.resolve())


def test_is_within_directory_rejects_paths_outside_project(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()

    assert _is_within_directory(project, project)
    assert _is_within_directory(project / "requirements.txt", project)
    assert not _is_within_directory(outside / "requirements.txt", project)


def test_manifest_symlink_outside_project_is_skipped(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    outside = tmp_path / "outside-requirements.txt"
    _write(outside, "requests>=2.31.0\n")
    link = project / "requirements.txt"

    try:
        os.symlink(outside, link)
    except (OSError, NotImplementedError):
        pytest.skip("symbolic links are not available in this environment")

    assert detect_manifests(project) == []

    result = discover_dependencies(project)

    assert result["status"] == STATUS_PARTIAL
    assert result["dependencies"] == []
    assert result["manifests"][0]["status"] == "skipped"
    assert "outside the project directory" in result["warnings"][0]


def test_manifest_symlink_inside_project_is_allowed(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    target = project / "requirements-base.txt"
    _write(target, "requests>=2.31.0\n")
    link = project / "requirements.txt"

    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("symbolic links are not available in this environment")

    result = discover_dependencies(project)

    assert result["status"] == STATUS_PARTIAL
    assert result["dependency_count"] == 1
    assert result["inventory"][0]["normalized_name"] == "requests"


def test_inventory_deduplicates_across_manifests_and_preserves_references(tmp_path):
    _write(tmp_path / "requirements.txt", "Requests>=2.31.0\nflask\n")
    _write(
        tmp_path / "pyproject.toml",
        """
[project]
name = "demo"
dependencies = ["requests>=2.31.0", "packaging>=24.0"]
""",
    )

    result = discover_dependencies(tmp_path)

    assert result["status"] == STATUS_PARTIAL
    assert result["dependency_count"] == 4
    assert result["unique_dependency_count"] == 3
    assert [item["normalized_name"] for item in result["inventory"]] == [
        "flask",
        "packaging",
        "requests",
    ]

    requests_entry = next(
        item for item in result["inventory"] if item["normalized_name"] == "requests"
    )
    assert requests_entry["source_manifests"] == ["pyproject.toml", "requirements.txt"]
    assert len(requests_entry["declarations"]) == 2
    assert {item["source_manifest"] for item in requests_entry["declarations"]} == {
        "pyproject.toml",
        "requirements.txt",
    }
    assert requests_entry["version_constraints"] == [">=2.31.0"]
    assert requests_entry["dependency_types"] == ["regular"]


def test_inventory_merges_regular_and_optional_declarations(tmp_path):
    _write(
        tmp_path / "pyproject.toml",
        """
[project]
name = "demo"
dependencies = ["requests>=2.31.0"]

[project.optional-dependencies]
dev = ["requests[socks]>=2.31.0", "pytest>=8.0"]
""",
    )

    result = discover_dependencies(tmp_path)

    requests_entry = next(
        item for item in result["inventory"] if item["normalized_name"] == "requests"
    )
    assert requests_entry["dependency_types"] == ["optional", "regular"]
    assert requests_entry["optional_groups"] == ["dev"]
    assert len(requests_entry["declarations"]) == 2
    assert result["regular_dependency_count"] == 1
    assert result["optional_dependency_count"] == 2


def test_inventory_normalizes_package_name_variants(tmp_path):
    _write(
        tmp_path / "requirements.txt",
        "Zope.Interface>=5.0\nzope_interface>=5.0\n",
    )

    result = discover_dependencies(tmp_path)

    assert result["dependency_count"] == 2
    assert result["unique_dependency_count"] == 1
    assert result["inventory"][0]["normalized_name"] == "zope-interface"
    assert result["duplicates"][0]["kind"] == "duplicate"


def test_duplicate_detection_includes_optional_group(tmp_path):
    _write(
        tmp_path / "pyproject.toml",
        """
[project]
name = "demo"

[project.optional-dependencies]
dev = ["requests>=2.31.0"]
docs = ["requests>=2.31.0"]
""",
    )

    result = discover_dependencies(tmp_path)

    assert result["dependency_count"] == 2
    assert result["unique_dependency_count"] == 1
    assert result["duplicates"][0]["kind"] == "conflict"
    assert result["duplicates"][0]["count"] == 2
    assert {
        item["optional_group"]
        for item in result["duplicates"][0]["declarations"]
    } == {"dev", "docs"}


def test_discovery_aliases_return_the_same_shape(tmp_path):
    _write(tmp_path / "requirements.txt", "flask\n")

    discovered = discover_dependencies(tmp_path)
    projected = discover_project(tmp_path)
    scanned = scan_project(tmp_path)

    assert discovered["inventory"] == projected["inventory"] == scanned["inventory"]
    assert discovered["status"] == projected["status"] == scanned["status"]


def test_discovery_returns_no_manifests_for_unsupported_project(tmp_path):
    _write(tmp_path / "package.json", "{}")

    result = discover_dependencies(tmp_path)

    assert result["status"] == STATUS_NO_MANIFESTS
    assert result["manifests"] == []
    assert result["inventory"] == []
    assert result["unique_dependency_count"] == 0


def test_discovery_returns_partial_for_malformed_pyproject(tmp_path):
    _write(tmp_path / "pyproject.toml", "[project\ndependencies = [\n")

    result = discover_dependencies(tmp_path)

    assert result["status"] == STATUS_PARTIAL
    assert result["manifests"][0]["status"] == "parsed"
    assert any("malformed TOML" in warning for warning in result["warnings"])
    assert result["inventory"] == []


def test_discovery_handles_empty_manifests(tmp_path):
    _write(tmp_path / "requirements.txt", "")
    _write(tmp_path / "pyproject.toml", "[project]\nname = 'demo'\n")

    result = discover_dependencies(tmp_path)

    assert result["status"] == STATUS_PARTIAL
    assert result["manifests"][0]["dependency_count"] == 0
    assert result["manifests"][1]["dependency_count"] == 0
    assert result["dependencies"] == []
    assert result["inventory"] == []


@pytest.mark.parametrize(
    "project_directory",
    [None, "", "   "],
)
def test_discovery_rejects_missing_directory_values(project_directory):
    result = discover_dependencies(project_directory)

    assert result["status"] == STATUS_ERROR
    assert "no project directory" in result["warnings"][0]
    assert result["inventory"] == []


def test_discovery_rejects_non_directory_path(tmp_path):
    manifest = tmp_path / "requirements.txt"
    _write(manifest, "flask\n")

    result = discover_dependencies(manifest)

    assert result["status"] == STATUS_ERROR
    assert "is not a directory" in result["warnings"][0]


def test_discovery_rejects_nonexistent_directory(tmp_path):
    missing = tmp_path / "missing project"

    result = discover_dependencies(missing)

    assert result["status"] == STATUS_ERROR
    assert result["warnings"] == ["could not access project directory"]


def test_discovery_reports_inaccessible_directory(tmp_path, monkeypatch):
    project = tmp_path / "inaccessible project"
    project.mkdir()
    original_scandir = os.scandir

    def deny_project_directory(path):
        if Path(path) == project.resolve():
            raise PermissionError("access denied")
        return original_scandir(path)

    monkeypatch.setattr(dependency_discovery.os, "scandir", deny_project_directory)

    result = discover_dependencies(project)

    assert result["status"] == STATUS_ERROR
    assert result["warnings"] == ["project directory could not be read"]
