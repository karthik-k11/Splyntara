"""Focused regression tests for application hardening and reliability."""

import re
from pathlib import Path
from unittest.mock import patch

import pytest

import app as app_module
from app import MAX_PROJECT_DIRECTORY_LENGTH
from services import (
    dependency_discovery,
    sbom_generator,
    security_dashboard,
    vulnerability_scanner,
)
from services.dependency_discovery import STATUS_ERROR, STATUS_PARTIAL
from services.osv_client import (
    OSVClient,
    OSVInvalidResponseError,
)

DISCOVERY_ENDPOINT = "/api/dependencies/discover"
DASHBOARD_ENDPOINT = "/api/dashboard/analyze"
REPORT_ENDPOINT = "/api/reports/security"
SBOM_DOWNLOAD_ENDPOINT = "/api/sbom/download"


def _write(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self.payload = payload
        self.status_code = status_code

    def json(self):
        return self.payload


class FakeOSVClient:
    def __init__(self, *, batch_results=None, details=None):
        self.batch_results = batch_results or []
        self.details = details or {}
        self.detail_calls = []

    def query_batch(self, queries):
        return self.batch_results

    def get_vulnerability(self, vulnerability_id):
        self.detail_calls.append(vulnerability_id)
        return self.details[vulnerability_id]


def _detail(vulnerability_id="GHSA-HARDEN", *, package_name="requests"):
    return {
        "id": vulnerability_id,
        "summary": "Example advisory",
        "details": "Detailed advisory text.",
        "aliases": ["CVE-2026-9999"],
        "published": "2026-01-01T00:00:00Z",
        "modified": "2026-01-02T00:00:00Z",
        "severity": [{"type": "CVSS_V3", "score": "9.8"}],
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": package_name},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "9.9.9"}],
                    }
                ],
            }
        ],
        "references": [
            {"type": "ADVISORY", "url": "https://example.com/advisory"},
        ],
        "database_specific": {"severity": "CRITICAL"},
    }


def test_local_server_disables_debug_mode(monkeypatch):
    calls = {}

    class FakeApplication:
        def run(self, **kwargs):
            calls.update(kwargs)

    monkeypatch.setattr(app_module, "create_app", lambda: FakeApplication())

    app_module.run_local_server()

    assert calls == {
        "host": "127.0.0.1",
        "port": 5000,
        "debug": False,
    }


def test_security_headers_are_added_to_responses(client):
    response = client.get("/health")

    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"


def test_unknown_api_route_returns_structured_json_404(client):
    response = client.get("/api/does-not-exist")

    assert response.status_code == 404
    assert response.mimetype == "application/json"
    payload = response.get_json()
    assert payload["status"] == "error"
    assert payload["error"] == "not found"
    assert "does-not-exist" not in response.get_data(as_text=True)


def test_wrong_api_method_returns_structured_json_405(client):
    response = client.get(DASHBOARD_ENDPOINT)

    assert response.status_code == 405
    assert response.mimetype == "application/json"
    assert response.get_json()["error"] == "method not allowed"


def test_oversized_request_returns_structured_json_413(client, monkeypatch):
    monkeypatch.setitem(client.application.config, "MAX_CONTENT_LENGTH", 64)

    response = client.post(
        DISCOVERY_ENDPOINT,
        data=b"x" * 128,
        content_type="application/json",
    )

    assert response.status_code == 413
    assert response.mimetype == "application/json"
    payload = response.get_json()
    assert payload["status"] == "error"
    assert payload["error"] == "request body is too large"
    assert "x" * 128 not in response.get_data(as_text=True)


@pytest.mark.parametrize(
    ("endpoint", "function_name"),
    [
        (DISCOVERY_ENDPOINT, "discover_dependencies"),
        (DASHBOARD_ENDPOINT, "analyze_security_dashboard"),
    ],
)
def test_unexpected_service_exceptions_are_sanitized(
    client,
    tmp_path,
    monkeypatch,
    endpoint,
    function_name,
):
    secret = "secret-internal-detail"
    internal_path = "C:/internal/private/path"

    def explode(_project_directory):
        raise RuntimeError(f"{secret} {internal_path}")

    monkeypatch.setattr(app_module, function_name, explode)
    _write(tmp_path / "requirements.txt", "flask\n")

    response = client.post(endpoint, json={"project_directory": str(tmp_path)})

    assert response.status_code == 500
    payload = response.get_json()
    assert payload["status"] == "error"
    assert payload["error"] == "internal server error"
    body = response.get_data(as_text=True)
    assert secret not in body
    assert internal_path not in body
    assert "RuntimeError" not in body


@pytest.mark.parametrize(
    "body",
    [
        b"{not-json",
        b"[]",
        b'"just-a-string"',
        b"null",
    ],
)
def test_malformed_or_non_object_json_is_rejected(client, tmp_path, body):
    _write(tmp_path / "requirements.txt", "flask\n")
    response = client.post(
        f"{DISCOVERY_ENDPOINT}?project_directory={tmp_path}",
        data=body,
        content_type="application/json",
    )

    assert response.status_code == 400
    assert response.mimetype == "application/json"
    payload = response.get_json()
    assert payload["status"] == "error"
    assert payload["error"] == "request body must be a JSON object"


def test_query_parameter_requests_remain_supported(client, tmp_path):
    _write(tmp_path / "requirements.txt", "flask\n")

    response = client.get(
        DISCOVERY_ENDPOINT,
        query_string={"project_directory": str(tmp_path)},
    )

    assert response.status_code == 200
    assert response.get_json()["dependency_count"] == 1


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ({}, "project_directory is required"),
        ({"project_directory": None}, "project_directory is required"),
        ({"project_directory": 123}, "project_directory must be a string"),
        ({"project_directory": "   "}, "project_directory must not be empty"),
    ],
)
def test_invalid_project_directory_values_are_rejected(client, payload, message):
    response = client.post(DISCOVERY_ENDPOINT, json=payload)

    assert response.status_code == 400
    assert response.get_json()["error"] == message


def test_overlong_project_directory_is_rejected_without_echoing_it(client):
    value = "a" * (MAX_PROJECT_DIRECTORY_LENGTH + 1)

    response = client.post(
        DISCOVERY_ENDPOINT,
        json={"project_directory": value},
    )

    assert response.status_code == 400
    payload = response.get_json()
    assert payload["error"] == "project_directory is too long"
    assert value not in response.get_data(as_text=True)


def test_null_byte_project_directory_is_rejected(client):
    response = client.post(
        DISCOVERY_ENDPOINT,
        json={"project_directory": "project\x00directory"},
    )

    assert response.status_code == 400
    assert response.get_json()["error"] == (
        "project_directory contains invalid characters"
    )


def test_missing_directory_error_does_not_expose_os_details(client, tmp_path):
    missing = tmp_path / "missing-project"

    response = client.post(
        DISCOVERY_ENDPOINT,
        json={"project_directory": str(missing)},
    )

    assert response.status_code == 400
    payload = response.get_json()
    assert payload["error"] == "could not access project directory"
    disclosures = [payload["error"], *payload["warnings"]]
    assert all("WinError" not in item for item in disclosures)
    assert all("[Errno" not in item for item in disclosures)
    assert all(str(missing) not in item for item in disclosures)


def test_unreadable_project_directory_reports_generic_error(tmp_path, monkeypatch):
    def fail_scandir(_path):
        raise PermissionError("secret /internal/path")

    monkeypatch.setattr(dependency_discovery.os, "scandir", fail_scandir)

    result = dependency_discovery.discover_dependencies(tmp_path)

    assert result["status"] == STATUS_ERROR
    assert result["warnings"] == ["project directory could not be read"]


def test_non_regular_manifest_is_reported_and_skipped(tmp_path):
    (tmp_path / "requirements.txt").mkdir()

    result = dependency_discovery.discover_dependencies(tmp_path)

    assert result["status"] == STATUS_PARTIAL
    assert result["dependencies"] == []
    assert result["manifests"][0]["status"] == "skipped"
    assert "not a regular file" in result["warnings"][0]


def test_manifest_larger_than_limit_is_skipped(tmp_path, monkeypatch):
    monkeypatch.setattr(dependency_discovery, "MAX_MANIFEST_BYTES", 32)
    _write(
        tmp_path / "requirements.txt",
        "requests>=2.31.0\n" * 10,
    )

    result = dependency_discovery.discover_dependencies(tmp_path)

    assert result["status"] == STATUS_PARTIAL
    assert result["dependency_count"] == 0
    assert result["manifests"][0]["status"] == "skipped"
    assert "size limit" in result["warnings"][0]


def test_invalid_utf8_manifest_warning_does_not_include_project_path(tmp_path):
    (tmp_path / "requirements.txt").write_bytes(b"\xff\xfe\x00\x01")

    result = dependency_discovery.discover_dependencies(tmp_path)

    warning = result["warnings"][0]
    assert "could not be read" in warning
    assert str(tmp_path) not in warning


def test_parser_exception_is_sanitized(tmp_path, monkeypatch):
    secret = "secret /internal/parser/path"

    def fail_parser(*_args, **_kwargs):
        raise RuntimeError(secret)

    monkeypatch.setitem(
        dependency_discovery.MANIFEST_PARSERS,
        "requirements.txt",
        ("requirements", fail_parser),
    )
    _write(tmp_path / "requirements.txt", "requests\n")

    result = dependency_discovery.discover_dependencies(tmp_path)

    assert result["status"] == STATUS_PARTIAL
    assert result["manifests"][0]["status"] == "failed"
    assert "unexpected error while parsing" in result["warnings"][0]
    assert secret not in result["warnings"][0]


def test_sbom_serialization_error_is_sanitized(monkeypatch):
    secret = "secret /internal/serializer/path"

    def fail_outputter(*_args, **_kwargs):
        raise RuntimeError(secret)

    monkeypatch.setattr(sbom_generator, "make_outputter", fail_outputter)

    result = sbom_generator.build_sbom({
        "status": "success",
        "project_directory": "/demo",
        "project_name": "demo",
        "warnings": [],
        "inventory": [
            {
                "name": "requests",
                "normalized_name": "requests",
                "declarations": [],
            }
        ],
    })

    assert result["status"] == STATUS_ERROR
    assert result["sbom"] is None
    assert result["error"] == "could not generate SBOM"
    assert all(secret not in warning for warning in result["warnings"])


def test_osv_detail_response_id_must_match_requested_id():
    response = FakeResponse({"id": "GHSA-OTHER", "summary": "Wrong advisory"})

    with patch("services.osv_client.requests.get", return_value=response):
        with pytest.raises(OSVInvalidResponseError):
            OSVClient().get_vulnerability("GHSA-REQUESTED")


def test_scanner_fetches_duplicate_advisory_detail_only_once():
    discovery = {
        "status": "success",
        "project_directory": "/demo",
        "project_name": "demo",
        "warnings": [],
        "inventory": [
            {
                "name": "requests",
                "normalized_name": "requests",
                "version": "2.31.0",
            },
            {
                "name": "flask",
                "normalized_name": "flask",
                "version": "3.0.0",
            },
        ],
    }
    fake_client = FakeOSVClient(
        batch_results=[
            {"vulns": [{"id": "GHSA-HARDEN"}]},
            {"vulns": [{"id": "GHSA-HARDEN"}]},
        ],
        details={"GHSA-HARDEN": _detail()},
    )

    result = vulnerability_scanner.build_vulnerability_report(
        discovery,
        client=fake_client,
    )

    assert fake_client.detail_calls == ["GHSA-HARDEN"]
    assert result["total_vulnerability_count"] == 2


def test_scanner_rejects_mismatched_detail_id():
    discovery = {
        "status": "success",
        "project_directory": "/demo",
        "project_name": "demo",
        "warnings": [],
        "inventory": [
            {
                "name": "requests",
                "normalized_name": "requests",
                "version": "2.31.0",
            },
        ],
    }
    fake_client = FakeOSVClient(
        batch_results=[{"vulns": [{"id": "GHSA-HARDEN"}]}],
        details={
            "GHSA-HARDEN": _detail("GHSA-OTHER"),
        },
    )

    result = vulnerability_scanner.build_vulnerability_report(
        discovery,
        client=fake_client,
    )

    assert result["vulnerabilities"] == []
    assert any("did not match" in error for error in result["errors"])


def test_html_report_escapes_untrusted_advisory_and_package_text(
    client,
    tmp_path,
    monkeypatch,
):
    package_name = "<script>alert('package')</script>"
    summary = "<script>alert('summary')</script>"
    details = "<img src=x onerror=alert('details')>"
    reference_type = "<svg/onload=alert('reference')>"
    discovery = {
        "status": "success",
        "project_directory": str(tmp_path),
        "project_name": "demo",
        "warnings": ["<svg/onload=alert('warning')>"],
        "manifests": [],
        "inventory": [
            {
                "name": package_name,
                "normalized_name": package_name,
                "version": "1.0.0",
                "version_constraints": [],
                "source_manifests": ["requirements.txt"],
                "dependency_types": ["regular"],
                "declarations": [],
            }
        ],
    }
    detail = _detail(package_name=package_name)
    detail["summary"] = summary
    detail["details"] = details
    detail["references"] = [
        {"type": reference_type, "url": "https://example.com/advisory"},
        {"type": "WEB", "url": "javascript:alert('reference-url')"},
    ]

    monkeypatch.setattr(
        security_dashboard,
        "discover_dependencies",
        lambda _: discovery,
    )
    monkeypatch.setattr(
        vulnerability_scanner,
        "OSVClient",
        lambda: FakeOSVClient(
            batch_results=[{"vulns": [{"id": "GHSA-HARDEN"}]}],
            details={"GHSA-HARDEN": detail},
        ),
    )

    response = client.post(
        REPORT_ENDPOINT + "?format=html",
        json={"project_directory": str(tmp_path)},
    )

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert summary not in html
    assert details not in html
    assert package_name not in html
    assert reference_type not in html
    assert "javascript:alert('reference-url')" not in html
    assert "&lt;script&gt;alert" in html
    assert "&lt;svg/onload=alert" in html


def test_sbom_download_uses_safe_filename_and_headers(
    client,
    tmp_path,
    monkeypatch,
):
    malicious_name = 'bad"\r\nX-Injected: yes/../../evil'
    fake_result = {
        "status": "success",
        "project_name": malicious_name,
        "warnings": [],
        "sbom": {"bomFormat": "CycloneDX"},
    }
    monkeypatch.setattr(
        app_module,
        "generate_sbom",
        lambda _project_directory: fake_result,
    )

    response = client.post(
        SBOM_DOWNLOAD_ENDPOINT,
        json={"project_directory": str(tmp_path)},
    )

    assert response.status_code == 200
    disposition = response.headers["Content-Disposition"]
    assert re.fullmatch(
        r'attachment; filename="[a-z0-9._-]+-sbom\.json"',
        disposition,
    )
    assert "\r" not in disposition
    assert "\n" not in disposition
    assert "X-Injected" not in disposition
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Cache-Control"] == "no-store"


def test_report_download_uses_safe_filename(
    client,
    tmp_path,
    monkeypatch,
):
    malicious_name = 'report"\r\nX-Injected: yes/../../evil'
    monkeypatch.setattr(
        app_module,
        "analyze_security_dashboard",
        lambda _project_directory: {
            "status": "success",
            "report": {
                "format": "splyntara.security-report",
                "project": {"name": malicious_name},
            },
        },
    )

    response = client.post(
        REPORT_ENDPOINT,
        json={"project_directory": str(tmp_path)},
    )

    assert response.status_code == 200
    disposition = response.headers["Content-Disposition"]
    assert re.fullmatch(
        r'attachment; filename="[a-z0-9._-]+-security-report\.json"',
        disposition,
    )
    assert "X-Injected" not in disposition
    assert response.headers["X-Content-Type-Options"] == "nosniff"
