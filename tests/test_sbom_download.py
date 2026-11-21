"""Tests for the dashboard's downloadable CycloneDX SBOM endpoint."""

import json
from pathlib import Path

ENDPOINT = "/api/sbom/download"


def _write(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def test_post_downloads_cyclonedx_json(client, tmp_path):
    _write(tmp_path / "requirements.txt", "Flask>=3.1\nrequests==2.31.0\n")

    response = client.post(ENDPOINT, json={"project_directory": str(tmp_path)})

    assert response.status_code == 200
    assert response.mimetype == "application/json"
    disposition = response.headers["Content-Disposition"]
    assert disposition.startswith("attachment;")
    assert disposition.endswith('-sbom.json"')

    document = json.loads(response.get_data(as_text=True))
    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] == "1.5"
    assert document["metadata"]["component"]["name"] == tmp_path.name
    assert [component["purl"] for component in document["components"]] == [
        "pkg:pypi/flask",
        "pkg:pypi/requests",
    ]


def test_get_downloads_from_query_string(client, tmp_path):
    _write(tmp_path / "requirements.txt", "flask\n")

    response = client.get(
        ENDPOINT,
        query_string={"project_directory": str(tmp_path)},
    )

    assert response.status_code == 200
    document = json.loads(response.get_data(as_text=True))
    assert document["components"][0]["purl"] == "pkg:pypi/flask"


def test_empty_project_still_returns_valid_download(client, tmp_path):
    response = client.post(ENDPOINT, json={"project_directory": str(tmp_path)})

    assert response.status_code == 200
    document = json.loads(response.get_data(as_text=True))
    assert document["bomFormat"] == "CycloneDX"
    assert document.get("components", []) == []
    assert "attachment;" in response.headers["Content-Disposition"]


def test_rejects_missing_project_directory(client):
    response = client.post(ENDPOINT, json={})

    assert response.status_code == 400
    payload = response.get_json()
    assert payload["status"] == "error"
    assert payload["error"] == "project_directory is required"
    assert payload["sbom"] is None


def test_rejects_nonexistent_directory(client, tmp_path):
    missing = tmp_path / "does-not-exist"

    response = client.post(ENDPOINT, json={"project_directory": str(missing)})

    assert response.status_code == 400
    payload = response.get_json()
    assert "could not access project directory" in payload["error"]
    assert payload["sbom"] is None
