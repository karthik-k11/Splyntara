"""Tests for the vulnerability scanning API endpoint."""

from pathlib import Path

import pytest

from services import vulnerability_scanner
from services.osv_client import OSVTimeoutError

ENDPOINT = "/api/vulnerabilities/scan"


def _write(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


class FakeOSVClient:
    def __init__(self, *, batch_results=None, details=None, batch_error=None):
        self.batch_results = batch_results or []
        self.details = details or {}
        self.batch_error = batch_error
        self.queries = []

    def query_batch(self, queries):
        self.queries = queries
        if self.batch_error is not None:
            raise self.batch_error
        return self.batch_results

    def get_vulnerability(self, vulnerability_id):
        return self.details[vulnerability_id]


def _patch_client(monkeypatch, client):
    monkeypatch.setattr(vulnerability_scanner, "OSVClient", lambda: client)


def _resolved_entry(name, version, constraints=None):
    return {
        "name": name,
        "normalized_name": name,
        "version": version,
        "version_constraints": constraints or [],
        "declarations": [],
    }


def _patch_discovery(monkeypatch, project_directory, inventory):
    discovery_result = {
        "status": "success",
        "project_directory": str(project_directory),
        "project_name": project_directory.name,
        "warnings": [],
        "inventory": inventory,
    }
    monkeypatch.setattr(
        vulnerability_scanner,
        "discover_dependencies",
        lambda _: discovery_result,
    )


def _detail(vulnerability_id="GHSA-1111"):
    return {
        "id": vulnerability_id,
        "summary": "Example vulnerability",
        "details": "Detailed advisory text.",
        "aliases": ["CVE-2026-0001"],
        "published": "2026-01-01T00:00:00Z",
        "modified": "2026-01-02T00:00:00Z",
        "severity": [{"type": "CVSS_V3", "score": "7.5"}],
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "requests"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "2.32.0"}],
                    }
                ],
            }
        ],
        "references": [
            {
                "type": "ADVISORY",
                "url": f"https://osv.dev/vulnerability/{vulnerability_id}",
            }
        ],
        "database_specific": {"severity": "HIGH"},
    }


def test_post_scans_explicit_resolved_versions_and_returns_vulnerabilities(
    client,
    tmp_path,
    monkeypatch,
):
    fake_client = FakeOSVClient(
        batch_results=[{"vulns": [{"id": "GHSA-1111"}]}],
        details={"GHSA-1111": _detail()},
    )
    _patch_client(monkeypatch, fake_client)
    _patch_discovery(
        monkeypatch,
        tmp_path,
        [_resolved_entry("requests", "2.31.0", constraints=["==2.30.0"])],
    )

    response = client.post(ENDPOINT, json={"project_directory": str(tmp_path)})

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "success"
    assert payload["project_name"] == tmp_path.name
    assert payload["total_dependencies_checked"] == 1
    assert payload["vulnerable_dependency_count"] == 1
    assert payload["total_vulnerability_count"] == 1
    assert payload["vulnerabilities"][0]["package_name"] == "requests"
    assert payload["vulnerabilities"][0]["package_version"] == "2.31.0"
    assert payload["vulnerabilities"][0]["vulnerability_id"] == "GHSA-1111"
    assert payload["warnings"] == []
    assert payload["errors"] == []
    assert fake_client.queries == [
        {
            "package": {"name": "requests", "ecosystem": "PyPI"},
            "version": "2.31.0",
        }
    ]


def test_post_returns_empty_for_project_with_no_manifests(client, tmp_path):
    response = client.post(ENDPOINT, json={"project_directory": str(tmp_path)})

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "empty"
    assert payload["total_dependencies_checked"] == 0
    assert payload["vulnerabilities"] == []


@pytest.mark.parametrize(
    "manifest_line",
    [
        "requests==2.31.0\n",
        "requests>=2.31.0\n",
        "flask~=3.0\n",
    ],
)
def test_post_returns_partial_for_unresolved_versions(
    client,
    tmp_path,
    manifest_line,
):
    _write(tmp_path / "requirements.txt", manifest_line)

    response = client.post(ENDPOINT, json={"project_directory": str(tmp_path)})

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "partial"
    assert payload["total_dependencies_checked"] == 0
    assert payload["unresolved_dependency_count"] == 1
    assert payload["vulnerabilities"] == []
    assert any("no resolved version" in warning for warning in payload["warnings"])


def test_post_does_not_query_osv_for_exact_manifest_pin(
    client,
    tmp_path,
    monkeypatch,
):
    _write(tmp_path / "requirements.txt", "requests==2.31.0\n")
    fake_client = FakeOSVClient()
    _patch_client(monkeypatch, fake_client)

    response = client.post(ENDPOINT, json={"project_directory": str(tmp_path)})

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "partial"
    assert payload["total_dependencies_checked"] == 0
    assert payload["unresolved_dependency_count"] == 1
    assert payload["vulnerabilities"] == []
    assert fake_client.queries == []


def test_post_handles_osv_timeout_without_crashing(client, tmp_path, monkeypatch):
    fake_client = FakeOSVClient(batch_error=OSVTimeoutError("OSV request timed out"))
    _patch_client(monkeypatch, fake_client)
    _patch_discovery(monkeypatch, tmp_path, [_resolved_entry("requests", "2.31.0")])

    response = client.post(ENDPOINT, json={"project_directory": str(tmp_path)})

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "partial"
    assert payload["total_dependencies_checked"] == 0
    assert payload["vulnerabilities"] == []
    assert payload["errors"] == ["OSV request timed out"]


def test_post_rejects_missing_project_directory(client):
    response = client.post(ENDPOINT, json={})

    assert response.status_code == 400
    payload = response.get_json()
    assert payload["status"] == "error"
    assert payload["error"] == "project_directory is required"
    assert payload["total_dependencies_checked"] == 0
    assert payload["vulnerabilities"] == []


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
    assert payload["vulnerabilities"] == []


def test_post_rejects_file_path(client, tmp_path):
    file_path = tmp_path / "requirements.txt"
    _write(file_path, "requests==2.31.0\n")

    response = client.post(ENDPOINT, json={"project_directory": str(file_path)})

    assert response.status_code == 400
    assert "is not a directory" in response.get_json()["error"]


def test_post_accepts_directory_alias(client, tmp_path, monkeypatch):
    fake_client = FakeOSVClient(batch_results=[{"vulns": []}])
    _patch_client(monkeypatch, fake_client)
    _patch_discovery(monkeypatch, tmp_path, [_resolved_entry("requests", "2.31.0")])

    response = client.post(ENDPOINT, json={"directory": str(tmp_path)})

    assert response.status_code == 200
    assert response.get_json()["total_dependencies_checked"] == 1


def test_non_post_methods_are_not_exposed(client):
    response = client.get(ENDPOINT)

    assert response.status_code == 405


def test_health_endpoint_remains_available(client):
    response = client.get("/health")

    assert response.status_code == 200
    assert response.get_json() == {"status": "ok", "application": "Splyntara"}
