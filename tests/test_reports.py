"""Tests for security report generation and downloadable exports."""

import json
from pathlib import Path

from services import security_dashboard, vulnerability_scanner

ENDPOINT = "/api/reports/security"


def _write(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


class FakeOSVClient:
    def __init__(self, *, batch_results=None, details=None):
        self.batch_results = batch_results or []
        self.details = details or {}
        self.batch_calls = 0

    def query_batch(self, queries):
        self.batch_calls += 1
        return self.batch_results

    def get_vulnerability(self, vulnerability_id):
        return self.details[vulnerability_id]


def _detail():
    return {
        "id": "GHSA-2222",
        "summary": "Example insecure parser",
        "details": "Detailed advisory text.",
        "aliases": ["CVE-2026-0002"],
        "published": "2026-01-01T00:00:00Z",
        "modified": "2026-01-02T00:00:00Z",
        "severity": [{"type": "CVSS_V3", "score": "9.1"}],
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
                "url": "https://osv.dev/vulnerability/GHSA-2222",
            },
            {
                "type": "WEB",
                "url": "javascript:alert(1)",
            },
        ],
        "database_specific": {"severity": "CRITICAL"},
    }


def _patch_resolved_project(monkeypatch, project_directory):
    discovery = {
        "status": "success",
        "project_directory": str(project_directory),
        "project_name": project_directory.name,
        "warnings": [],
        "manifests": [
            {
                "filename": "requirements.txt",
                "format": "requirements",
                "path": str(project_directory / "requirements.txt"),
                "dependency_count": 1,
                "status": "parsed",
            }
        ],
        "inventory": [
            {
                "name": "requests",
                "normalized_name": "requests",
                "version": "2.31.0",
                "version_constraints": ["==2.30.1"],
                "source_manifests": ["requirements.txt"],
                "dependency_types": ["regular"],
                "declarations": [
                    {
                        "source_manifest": "requirements.txt",
                        "version_constraint": "==2.30.1",
                    }
                ],
            }
        ],
    }
    monkeypatch.setattr(
        security_dashboard,
        "discover_dependencies",
        lambda _: discovery,
    )
    fake_client = FakeOSVClient(
        batch_results=[{"vulns": [{"id": "GHSA-2222"}]}],
        details={"GHSA-2222": _detail()},
    )
    monkeypatch.setattr(
        vulnerability_scanner,
        "OSVClient",
        lambda: fake_client,
    )
    return fake_client


def test_json_report_export_is_downloadable(client, tmp_path, monkeypatch):
    fake_client = _patch_resolved_project(monkeypatch, tmp_path)

    response = client.post(ENDPOINT, json={"project_directory": str(tmp_path)})

    assert response.status_code == 200
    assert response.mimetype == "application/json"
    disposition = response.headers["Content-Disposition"]
    assert disposition.startswith("attachment;")
    assert disposition.endswith('-security-report.json"')

    report = json.loads(response.get_data(as_text=True))
    assert report["format"] == "splyntara.security-report"
    assert report["project"]["name"] == tmp_path.name
    assert report["project"]["manifests"][0]["filename"] == "requirements.txt"
    assert report["scan_summary"]["total_dependencies"] == 1
    assert report["scan_summary"]["total_vulnerabilities"] == 1
    assert report["scan_summary"]["project_risk"] == "Critical"
    assert report["inventory"][0]["declared_constraints"] == ["==2.30.1"]
    assert report["inventory"][0]["manifest_sources"] == ["requirements.txt"]
    assert report["vulnerabilities"][0]["vulnerability_id"] == "GHSA-2222"
    assert report["vulnerabilities"][0]["fixed_versions"] == ["2.32.0"]
    assert len(report["vulnerabilities"][0]["references"]) == 1
    assert report["vulnerabilities"][0]["references"][0]["url"].startswith(
        "https://"
    )
    assert report["risk"]["dependencies"][0]["reasons"]
    assert report["coverage"]["status"] == "complete"
    assert fake_client.batch_calls == 1


def test_html_report_export_is_downloadable(client, tmp_path, monkeypatch):
    _patch_resolved_project(monkeypatch, tmp_path)

    response = client.post(
        ENDPOINT + "?format=html",
        json={"project_directory": str(tmp_path)},
    )

    assert response.status_code == 200
    assert response.mimetype == "text/html"
    disposition = response.headers["Content-Disposition"]
    assert disposition.startswith("attachment;")
    assert disposition.endswith('-security-report.html"')

    html = response.get_data(as_text=True)
    assert "<!doctype html>" in html
    assert "Dependency security assessment" in html
    assert tmp_path.name in html
    assert "GHSA-2222" in html
    assert "Critical" in html
    assert "Coverage limitations" in html
    assert "Known limitations" in html
    assert "javascript:alert(1)" not in html


def test_report_export_rejects_invalid_format(client, tmp_path):
    response = client.post(
        ENDPOINT + "?format=xml",
        json={"project_directory": str(tmp_path)},
    )

    assert response.status_code == 400
    payload = response.get_json()
    assert payload["status"] == "error"
    assert payload["error"] == "format must be 'json' or 'html'"


def test_report_export_rejects_missing_project_directory(client):
    response = client.post(ENDPOINT, json={})

    assert response.status_code == 400
    payload = response.get_json()
    assert payload["status"] == "error"
    assert payload["error"] == "project_directory is required"
    assert payload["report"] is None


def test_json_report_marks_unknown_risk_and_unresolved(
    client,
    tmp_path,
    monkeypatch,
):
    _write(tmp_path / "requirements.txt", "requests==2.31.0\n")
    fake_client = FakeOSVClient()
    monkeypatch.setattr(
        vulnerability_scanner,
        "OSVClient",
        lambda: fake_client,
    )

    response = client.post(ENDPOINT, json={"project_directory": str(tmp_path)})

    assert response.status_code == 200
    report = json.loads(response.get_data(as_text=True))
    assert report["scan_summary"]["project_risk"] == "Unknown"
    assert report["scan_summary"]["unresolved_dependencies"] == 1
    assert report["scan_summary"]["risk_counts"]["Unknown"] == 1
    assert report["inventory"][0]["resolved_version"] is None
    assert report["risk"]["dependencies"][0]["risk"] == "Unknown"
    assert any(
        "excluded from OSV scanning" in note
        for note in report["coverage"]["notes"]
    )
    assert fake_client.batch_calls == 0


def test_html_report_escapes_project_text(client, tmp_path, monkeypatch):
    discovery = {
        "status": "success",
        "project_directory": str(tmp_path),
        "project_name": "<script>alert(1)</script>",
        "warnings": [],
        "manifests": [],
        "inventory": [],
    }
    monkeypatch.setattr(
        security_dashboard,
        "discover_dependencies",
        lambda _: discovery,
    )
    monkeypatch.setattr(
        vulnerability_scanner,
        "OSVClient",
        lambda: FakeOSVClient(),
    )

    response = client.post(
        ENDPOINT + "?format=html",
        json={"project_directory": str(tmp_path)},
    )

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
