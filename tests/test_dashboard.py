"""Tests for the Day 7 security dashboard page and analysis API."""

from pathlib import Path

from services import security_dashboard, vulnerability_scanner
from services.osv_client import OSVTimeoutError

ENDPOINT = "/api/dashboard/analyze"


def _write(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def _detail(vulnerability_id="GHSA-1111", severity="HIGH"):
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
        "database_specific": {"severity": severity},
    }


class FakeOSVClient:
    def __init__(self, *, batch_results=None, details=None, batch_error=None):
        self.batch_results = batch_results or []
        self.details = details or {}
        self.batch_error = batch_error
        self.batch_calls = 0
        self.queries = []

    def query_batch(self, queries):
        self.batch_calls += 1
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
        "source_manifests": ["requirements.txt"],
        "dependency_types": ["regular"],
        "declarations": [
            {
                "name": name,
                "normalized_name": name,
                "version_constraint": (constraints or [None])[0],
                "dependency_type": "regular",
                "source_manifest": "requirements.txt",
                "raw_declaration": name,
            }
        ],
    }


def _patch_discovery(monkeypatch, project_directory, inventory):
    discovery_result = {
        "status": "success",
        "project_directory": str(project_directory),
        "project_name": project_directory.name,
        "warnings": [],
        "manifests": [
            {
                "filename": "requirements.txt",
                "format": "requirements",
                "path": str(project_directory / "requirements.txt"),
                "dependency_count": len(inventory),
                "status": "parsed",
            }
        ],
        "inventory": inventory,
    }
    monkeypatch.setattr(
        security_dashboard,
        "discover_dependencies",
        lambda _: discovery_result,
    )


def test_dashboard_page_renders(client):
    response = client.get("/")

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Dependency security dashboard" in html
    assert 'id="analysis-form"' in html
    assert 'id="inventory-table"' in html
    assert 'id="vulnerability-table"' in html
    assert 'id="report-json"' in html
    assert 'id="history-list"' in html
    assert 'id="history-count"' in html
    assert 'class="history-summary"' in html
    assert 'class="icon"' in html
    assert "/static/css/dashboard.css" in html
    assert "/static/js/dashboard.js" in html


def test_dashboard_alias_renders_same_page(client):
    response = client.get("/dashboard")

    assert response.status_code == 200
    assert "Dependency security dashboard" in response.get_data(as_text=True)


def test_dashboard_static_assets_are_served(client):
    css = client.get("/static/css/dashboard.css")
    js = client.get("/static/js/dashboard.js")

    assert css.status_code == 200
    assert js.status_code == 200
    assert "--critical" in css.get_data(as_text=True)
    assert "runAnalysis" in js.get_data(as_text=True)


def test_analyze_returns_dashboard_and_report(client, tmp_path, monkeypatch):
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
    assert payload["project"]["name"] == tmp_path.name
    assert payload["project"]["manifests"][0]["filename"] == "requirements.txt"

    summary = payload["summary"]
    assert summary["total_dependencies"] == 1
    assert summary["vulnerable_dependencies"] == 1
    assert summary["total_vulnerabilities"] == 1
    assert summary["risk_counts"] == {
        "Critical": 0,
        "High": 1,
        "Medium": 0,
        "Low": 0,
        "Unknown": 0,
    }
    assert summary["unknown_risk_dependencies"] == 0
    assert summary["unresolved_dependencies"] == 0
    assert summary["incomplete_coverage_dependencies"] == 0
    assert summary["scan_coverage"] == "complete"
    assert summary["project_risk"] == "High"

    dependency = payload["dependencies"][0]
    assert dependency["package_name"] == "requests"
    assert dependency["declared_constraints"] == ["==2.30.0"]
    assert dependency["resolved_version"] == "2.31.0"
    assert dependency["manifest_sources"] == ["requirements.txt"]
    assert dependency["risk_classification"] == "High"
    assert dependency["vulnerability_count"] == 1

    finding = payload["vulnerabilities"][0]
    assert finding["vulnerability_id"] == "GHSA-1111"
    assert finding["fixed_versions"] == ["2.32.0"]
    assert finding["references"][0]["type"] == "ADVISORY"

    report = payload["report"]
    assert report["format"] == "splyntara.security-report"
    assert report["project"]["name"] == tmp_path.name
    assert report["scan_summary"]["project_risk"] == "High"
    assert report["inventory"][0]["manifest_sources"] == ["requirements.txt"]
    assert report["vulnerabilities"][0]["severity_label"] == "High"
    assert report["coverage"]["status"] == "complete"
    assert report["limitations"]

    assert "Dependency security assessment" in payload["report_html"]
    assert "GHSA-1111" in payload["report_html"]
    assert fake_client.batch_calls == 1
    assert fake_client.queries == [
        {
            "package": {"name": "requests", "ecosystem": "PyPI"},
            "version": "2.31.0",
        }
    ]


def test_analyze_accepts_explorer_quoted_windows_style_path_with_spaces(
    client,
    tmp_path,
    monkeypatch,
):
    project = tmp_path / "NMIMS VoiceAgent project"
    project.mkdir()
    _write(project / "requirements.txt", "requests>=2.31.0\n")
    fake_client = FakeOSVClient()
    _patch_client(monkeypatch, fake_client)

    response = client.post(
        ENDPOINT,
        json={"project_directory": f'"{project}"'},
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["project"]["directory"] == str(project.resolve())
    assert payload["status"] == "partial"
    assert fake_client.batch_calls == 0


def test_analyze_reports_unresolved_dependencies_without_osv(
    client,
    tmp_path,
    monkeypatch,
):
    _write(tmp_path / "requirements.txt", "requests==2.31.0\nflask>=3.0\n")
    fake_client = FakeOSVClient()
    _patch_client(monkeypatch, fake_client)

    response = client.post(ENDPOINT, json={"project_directory": str(tmp_path)})

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "partial"
    assert payload["summary"]["total_dependencies"] == 2
    assert payload["summary"]["unresolved_dependencies"] == 2
    assert payload["summary"]["risk_counts"]["Unknown"] == 2
    assert payload["summary"]["unknown_risk_dependencies"] == 2
    assert payload["summary"]["project_risk"] == "Unknown"
    assert payload["summary"]["scan_coverage"] == "unavailable"

    for dependency in payload["dependencies"]:
        assert dependency["resolved_version"] is None
        assert dependency["version_resolved"] is False
        assert dependency["risk_classification"] == "Unknown"
        assert dependency["scan_coverage"] == "unresolved"
        assert dependency["manifest_sources"] == ["requirements.txt"]

    report = payload["report"]
    assert report["summary"]["unknown_risk_dependencies"] == 2
    assert report["summary"]["unresolved_dependencies"] == 2
    assert report["coverage"]["notes"]
    assert any(
        "excluded from OSV scanning" in note
        for note in report["coverage"]["notes"]
    )
    assert "Unresolved" in payload["report_html"]
    assert "Unknown" in payload["report_html"]
    assert fake_client.batch_calls == 0
    assert fake_client.queries == []


def test_analyze_reports_empty_project(client, tmp_path, monkeypatch):
    fake_client = FakeOSVClient()
    _patch_client(monkeypatch, fake_client)

    response = client.post(ENDPOINT, json={"project_directory": str(tmp_path)})

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "empty"
    assert payload["summary"]["total_dependencies"] == 0
    assert payload["summary"]["scan_coverage"] == "empty"
    assert payload["dependencies"] == []
    assert payload["vulnerabilities"] == []
    assert payload["project"]["manifests"] == []
    assert payload["report"]["inventory"] == []
    assert "No dependencies were discovered" in payload["report_html"]
    assert fake_client.batch_calls == 0


def test_analyze_handles_osv_timeout(client, tmp_path, monkeypatch):
    fake_client = FakeOSVClient(batch_error=OSVTimeoutError("OSV request timed out"))
    _patch_client(monkeypatch, fake_client)
    _patch_discovery(
        monkeypatch,
        tmp_path,
        [_resolved_entry("requests", "2.31.0")],
    )

    response = client.post(ENDPOINT, json={"project_directory": str(tmp_path)})

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "partial"
    assert payload["summary"]["project_risk"] == "Unknown"
    assert payload["summary"]["scan_coverage"] == "unavailable"
    assert payload["summary"]["incomplete_coverage_dependencies"] == 1
    assert payload["dependencies"][0]["risk_classification"] == "Unknown"
    assert any("timed out" in error for error in payload["errors"])
    assert any("timed out" in error for error in payload["report"]["errors"])


def test_analyze_rejects_missing_project_directory(client):
    response = client.post(ENDPOINT, json={})

    assert response.status_code == 400
    payload = response.get_json()
    assert payload["status"] == "error"
    assert payload["error"] == "project_directory is required"
    assert payload["summary"]["total_dependencies"] == 0
    assert payload["report"] is None


def test_analyze_rejects_nonexistent_directory(client, tmp_path):
    missing = tmp_path / "does-not-exist"

    response = client.post(ENDPOINT, json={"project_directory": str(missing)})

    assert response.status_code == 400
    payload = response.get_json()
    assert "could not access project directory" in payload["error"]
    assert payload["dependencies"] == []


def test_analyze_rejects_file_path(client, tmp_path):
    file_path = tmp_path / "requirements.txt"
    _write(file_path, "requests==2.31.0\n")

    response = client.post(ENDPOINT, json={"project_directory": str(file_path)})

    assert response.status_code == 400
    assert "is not a directory" in response.get_json()["error"]
