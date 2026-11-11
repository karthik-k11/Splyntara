"""Tests for the dependency discovery scanner."""

from pathlib import Path

import pytest

from services.dependency_scanner import (
    FORMAT_PYPROJECT,
    FORMAT_REQUIREMENTS,
    STATUS_ERROR,
    STATUS_NO_MANIFESTS,
    STATUS_PARTIAL,
    STATUS_SUCCESS,
    detect_manifests,
    scan_project,
)


def _write(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def test_scan_project_detects_and_parses_requirements_txt(tmp_path):
    _write(tmp_path / "requirements.txt", "requests>=2.31.0\nflask\n")

    result = scan_project(tmp_path)

    assert result["status"] == STATUS_SUCCESS
    assert result["project_name"] == tmp_path.name
    assert result["dependency_count"] == 2
    assert result["regular_dependency_count"] == 2
    assert result["optional_dependency_count"] == 0
    assert [item["normalized_name"] for item in result["dependencies"]] == [
        "requests",
        "flask",
    ]
    assert [item["filename"] for item in result["manifests"]] == ["requirements.txt"]
    assert result["manifests"][0]["format"] == FORMAT_REQUIREMENTS


def test_scan_project_detects_and_parses_pyproject_toml(tmp_path):
    _write(
        tmp_path / "pyproject.toml",
        """
[project]
name = "demo"
dependencies = ["requests>=2.32.0"]

[project.optional-dependencies]
dev = ["pytest>=8.0"]
""",
    )

    result = scan_project(tmp_path)

    assert result["status"] == STATUS_SUCCESS
    assert result["dependency_count"] == 2
    assert result["regular_dependency_count"] == 1
    assert result["optional_dependency_count"] == 1
    assert result["manifests"][0]["format"] == FORMAT_PYPROJECT


def test_scan_project_processes_both_manifest_types(tmp_path):
    _write(tmp_path / "requirements.txt", "requests>=2.31.0\n")
    _write(
        tmp_path / "pyproject.toml",
        """
[project]
name = "demo"
dependencies = ["flask>=3.1"]
""",
    )

    result = scan_project(tmp_path)

    assert result["status"] == STATUS_SUCCESS
    assert result["dependency_count"] == 2
    sources = {item["source_manifest"] for item in result["dependencies"]}
    assert sources == {"requirements.txt", "pyproject.toml"}


def test_scan_project_returns_no_manifests_status(tmp_path):
    result = scan_project(tmp_path)

    assert result["status"] == STATUS_NO_MANIFESTS
    assert result["dependency_count"] == 0
    assert result["manifests"] == []
    assert result["dependencies"] == []


def test_scan_project_reports_missing_directory_as_error(tmp_path):
    result = scan_project(tmp_path / "does-not-exist")

    assert result["status"] == STATUS_ERROR
    assert result["dependency_count"] == 0
    assert len(result["warnings"]) == 1
    assert "could not access" in result["warnings"][0]


def test_scan_project_reports_file_path_as_error(tmp_path):
    file_path = tmp_path / "a_file.txt"
    _write(file_path, "not a directory")

    result = scan_project(file_path)

    assert result["status"] == STATUS_ERROR
    assert "is not a directory" in result["warnings"][0]


def test_scan_project_reports_empty_path_as_error():
    result = scan_project("")

    assert result["status"] == STATUS_ERROR
    assert "no project directory" in result["warnings"][0]


def test_scan_project_reports_unreadable_manifest_as_partial(tmp_path):
    (tmp_path / "requirements.txt").write_bytes(b"\xff\xfe\x00\x01")

    result = scan_project(tmp_path)

    assert result["status"] == STATUS_PARTIAL
    assert result["dependency_count"] == 0
    assert result["manifests"][0]["status"] == "unreadable"
    assert "could not be read" in result["warnings"][0]


def test_scan_project_handles_malformed_toml_as_partial(tmp_path):
    _write(tmp_path / "pyproject.toml", "[project\ndependencies = [\n")

    result = scan_project(tmp_path)

    assert result["status"] == STATUS_PARTIAL
    assert result["dependency_count"] == 0
    assert any("malformed TOML" in warning for warning in result["warnings"])


def test_scan_project_reports_exact_duplicates(tmp_path):
    _write(tmp_path / "requirements.txt", "requests>=2.31.0\nrequests>=2.31.0\n")

    result = scan_project(tmp_path)

    assert result["dependency_count"] == 2
    assert len(result["duplicates"]) == 1
    assert result["duplicates"][0]["normalized_name"] == "requests"
    assert result["duplicates"][0]["kind"] == "duplicate"


def test_scan_project_reports_conflicting_declarations(tmp_path):
    _write(
        tmp_path / "requirements.txt",
        "requests>=2.31.0\n",
    )
    _write(
        tmp_path / "pyproject.toml",
        """
[project]
name = "demo"
dependencies = ["requests>=3.0"]
""",
    )

    result = scan_project(tmp_path)

    assert result["dependency_count"] == 2
    assert len(result["duplicates"]) == 1
    duplicate = result["duplicates"][0]
    assert duplicate["kind"] == "conflict"
    assert duplicate["count"] == 2
    assert {item["source_manifest"] for item in duplicate["declarations"]} == {
        "requirements.txt",
        "pyproject.toml",
    }


def test_detect_manifests_identifies_formats(tmp_path):
    _write(tmp_path / "requirements.txt", "requests\n")
    _write(tmp_path / "pyproject.toml", "[project]\nname = 'demo'\n")

    manifests = detect_manifests(tmp_path)

    assert [item["filename"] for item in manifests] == [
        "requirements.txt",
        "pyproject.toml",
    ]
    assert [item["format"] for item in manifests] == [
        FORMAT_REQUIREMENTS,
        FORMAT_PYPROJECT,
    ]


def test_detect_manifests_raises_for_invalid_directory(tmp_path):
    with pytest.raises(ValueError):
        detect_manifests(tmp_path / "missing")


def test_scan_project_does_not_remove_dependencies_when_duplicated(tmp_path):
    _write(
        tmp_path / "requirements.txt",
        "requests>=2.31.0\nrequests>=2.31.0\nflask\n",
    )

    result = scan_project(tmp_path)

    assert result["dependency_count"] == 3
    assert [item["normalized_name"] for item in result["dependencies"]] == [
        "requests",
        "requests",
        "flask",
    ]
