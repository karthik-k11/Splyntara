"""Tests for the CycloneDX SBOM API endpoint."""

import json
from pathlib import Path

import pytest
from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonValidator

ENDPOINT = "/api/sbom/generate"


def _write(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def _validate(document):
    validator = JsonValidator(SchemaVersion.V1_5)
    error = validator.validate_str(json.dumps(document))
    assert error is None


def test_post_generates_sbom_for_requirements_project(client, tmp_path):
    _write(tmp_path / "requirements.txt", "Flask>=3.1\nrequests==2.31.0\n")

    response = client.post(ENDPOINT, json={"project_directory": str(tmp_path)})

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["bomFormat"] == "CycloneDX"
    assert payload["specVersion"] == "1.5"
    assert payload["metadata"]["component"]["name"] == tmp_path.name
    assert [component["purl"] for component in payload["components"]] == [
        "pkg:pypi/flask",
        "pkg:pypi/requests",
    ]
    _validate(payload)


def test_get_generates_sbom_from_query_string(client, tmp_path):
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
    assert {
        component["purl"] for component in payload["components"]
    } == {"pkg:pypi/requests", "pkg:pypi/pytest"}
    _validate(payload)


def test_post_supports_sbom_endpoint_alias(client, tmp_path):
    _write(tmp_path / "requirements.txt", "flask\n")

    response = client.post("/api/sbom", json={"project_directory": str(tmp_path)})

    assert response.status_code == 200
    assert response.get_json()["bomFormat"] == "CycloneDX"


def test_post_supports_short_endpoint_alias(client, tmp_path):
    _write(tmp_path / "requirements.txt", "flask\n")

    response = client.post(
        "/sbom/generate",
        json={"project_directory": str(tmp_path)},
    )

    assert response.status_code == 200
    assert response.get_json()["bomFormat"] == "CycloneDX"


def test_post_generates_empty_but_valid_sbom(client, tmp_path):
    response = client.post(ENDPOINT, json={"project_directory": str(tmp_path)})

    assert response.status_code == 200
    payload = response.get_json()
    assert payload.get("components", []) == []
    _validate(payload)


def test_post_generates_sbom_for_partial_discovery(client, tmp_path):
    _write(tmp_path / "requirements.txt", "requests>=2.31.0\nnot valid!!\n")

    response = client.post(ENDPOINT, json={"project_directory": str(tmp_path)})

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["components"][0]["purl"] == "pkg:pypi/requests"
    properties = payload["metadata"]["properties"]
    assert any(
        item["name"] == "splyntara:warning" and "could not parse" in item["value"]
        for item in properties
    )
    _validate(payload)


def test_post_rejects_missing_project_directory(client):
    response = client.post(ENDPOINT, json={})

    assert response.status_code == 400
    payload = response.get_json()
    assert payload["status"] == "error"
    assert payload["error"] == "project_directory is required"
    assert payload["sbom"] is None


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
    assert payload["status"] == "error"
    assert "could not access project directory" in payload["error"]
    assert payload["sbom"] is None


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
    assert response.get_json()["bomFormat"] == "CycloneDX"


def test_health_endpoint_remains_available(client):
    response = client.get("/health")

    assert response.status_code == 200
    assert response.get_json() == {"status": "ok", "application": "Splyntara"}
