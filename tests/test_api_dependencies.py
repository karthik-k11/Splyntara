"""Tests for the dependency discovery API endpoint."""

from pathlib import Path

import pytest

from services.dependency_discovery import (
    STATUS_ERROR,
    STATUS_NO_MANIFESTS,
    STATUS_PARTIAL,
    STATUS_SUCCESS,
)

ENDPOINT = "/api/dependencies/discover"


def _write(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def test_post_discovers_requirements_dependencies(client, tmp_path):
    _write(tmp_path / "requirements.txt", "Flask>=3.1,<4.0\nrequests\n")

    response = client.post(ENDPOINT, json={"project_directory": str(tmp_path)})

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == STATUS_SUCCESS
    assert payload["project_name"] == tmp_path.name
    assert payload["dependency_count"] == 2
    assert payload["unique_dependency_count"] == 2
    assert [item["normalized_name"] for item in payload["inventory"]] == [
        "flask",
        "requests",
    ]
    assert payload["manifests"][0]["filename"] == "requirements.txt"
    assert payload["manifests"][0]["status"] == "parsed"


def test_get_discovers_pyproject_dependencies_from_query_string(client, tmp_path):
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

    response = client.get(ENDPOINT, query_string={"project_directory": str(tmp_path)})

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == STATUS_SUCCESS
    assert payload["regular_dependency_count"] == 1
    assert payload["optional_dependency_count"] == 1
    assert {item["normalized_name"] for item in payload["inventory"]} == {
        "pytest",
        "requests",
    }


def test_post_combines_manifests_into_normalized_inventory(client, tmp_path):
    _write(tmp_path / "requirements.txt", "requests>=2.31.0\n")
    _write(
        tmp_path / "pyproject.toml",
        """
[project]
name = "demo"
dependencies = ["Requests>=3.0"]
""",
    )

    response = client.post(ENDPOINT, json={"project_directory": str(tmp_path)})

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["dependency_count"] == 2
    assert payload["unique_dependency_count"] == 1
    assert payload["inventory"][0]["source_manifests"] == [
        "pyproject.toml",
        "requirements.txt",
    ]
    assert payload["duplicates"][0]["kind"] == "conflict"


def test_post_returns_no_manifests_gracefully(client, tmp_path):
    _write(tmp_path / "package.json", "{}")

    response = client.post(ENDPOINT, json={"project_directory": str(tmp_path)})

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == STATUS_NO_MANIFESTS
    assert payload["manifests"] == []
    assert payload["inventory"] == []
    assert payload["dependency_count"] == 0


def test_post_returns_partial_for_invalid_pyproject(client, tmp_path):
    _write(tmp_path / "pyproject.toml", "[project\ndependencies = [\n")

    response = client.post(ENDPOINT, json={"project_directory": str(tmp_path)})

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == STATUS_PARTIAL
    assert any("malformed TOML" in warning for warning in payload["warnings"])


def test_post_rejects_missing_project_directory(client):
    response = client.post(ENDPOINT, json={})

    assert response.status_code == 400
    payload = response.get_json()
    assert payload["status"] == STATUS_ERROR
    assert payload["error"] == "project_directory is required"
    assert payload["inventory"] == []


def test_post_rejects_non_string_project_directory(client):
    response = client.post(ENDPOINT, json={"project_directory": 123})

    assert response.status_code == 400
    assert response.get_json()["error"] == "project_directory must be a string"


@pytest.mark.parametrize("value", ["", "   "])
def test_post_rejects_empty_project_directory(client, value):
    response = client.post(ENDPOINT, json={"project_directory": value})

    assert response.status_code == 400
    assert response.get_json()["error"] == "project_directory must not be empty"


def test_post_rejects_nonexistent_directory(client, tmp_path):
    missing = tmp_path / "does-not-exist"

    response = client.post(ENDPOINT, json={"project_directory": str(missing)})

    assert response.status_code == 400
    payload = response.get_json()
    assert payload["status"] == STATUS_ERROR
    assert "could not access project directory" in payload["error"]


def test_post_rejects_file_path(client, tmp_path):
    file_path = tmp_path / "requirements.txt"
    _write(file_path, "flask\n")

    response = client.post(ENDPOINT, json={"project_directory": str(file_path)})

    assert response.status_code == 400
    assert "is not a directory" in response.get_json()["error"]


def test_post_accepts_directory_alias(client, tmp_path):
    _write(tmp_path / "requirements.txt", "flask\n")

    response = client.post(ENDPOINT, json={"directory": str(tmp_path)})

    assert response.status_code == 200
    assert response.get_json()["dependency_count"] == 1


def test_post_accepts_path_alias(client, tmp_path):
    _write(tmp_path / "requirements.txt", "flask\n")

    response = client.post(ENDPOINT, json={"path": str(tmp_path)})

    assert response.status_code == 200
    assert response.get_json()["dependency_count"] == 1


def test_short_endpoint_alias_is_available(client, tmp_path):
    _write(tmp_path / "requirements.txt", "flask\n")

    response = client.post(
        "/dependencies/discover",
        json={"project_directory": str(tmp_path)},
    )

    assert response.status_code == 200
    assert response.get_json()["dependency_count"] == 1


def test_health_endpoint_still_works(client):
    response = client.get("/health")

    assert response.status_code == 200
    assert response.get_json() == {"status": "ok", "application": "Splyntara"}
