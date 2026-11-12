"""Tests for explainable dependency risk analysis."""

from pathlib import Path

import pytest

from services import risk_analyzer
from services.osv_client import OSVTimeoutError
from services.risk_analyzer import (
    COVERAGE_COMPLETE,
    COVERAGE_PARTIAL,
    COVERAGE_UNAVAILABLE,
    COVERAGE_UNRESOLVED,
    RISK_CRITICAL,
    RISK_HIGH,
    RISK_LOW,
    RISK_MEDIUM,
    RISK_UNKNOWN,
    STATUS_EMPTY,
    STATUS_ERROR,
    STATUS_PARTIAL,
    STATUS_SUCCESS,
    analyze_risks,
    build_risk_report,
)


def _write(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def _entry(
    name: str,
    version: str | None = None,
    constraints: list[str] | None = None,
) -> dict:
    entry = {
        "name": name,
        "normalized_name": name,
        "declarations": [],
    }

    if version is not None:
        entry["version"] = version

    if constraints is not None:
        entry["version_constraints"] = constraints

    return entry


def _discovery_result(
    inventory: list[dict],
    *,
    status: str = STATUS_SUCCESS,
    warnings: list[str] | None = None,
) -> dict:
    return {
        "status": status,
        "source_status": status,
        "project_directory": "C:/example/project",
        "project_name": "example-project",
        "inventory": inventory,
        "warnings": warnings or [],
    }


def _vulnerability_result(
    vulnerabilities: list[dict] | None = None,
    *,
    status: str = STATUS_SUCCESS,
    checked: int = 1,
    eligible: int = 1,
    unresolved: int = 0,
    warnings: list[str] | None = None,
    errors: list[str] | None = None,
) -> dict:
    findings = list(vulnerabilities or [])
    return {
        "status": status,
        "source_status": STATUS_SUCCESS,
        "project_directory": "C:/example/project",
        "project_name": "example-project",
        "inventory_count": checked + unresolved,
        "total_dependencies_checked": checked,
        "eligible_dependency_count": eligible,
        "unresolved_dependency_count": unresolved,
        "vulnerable_dependency_count": len({item["package_name"] for item in findings}),
        "total_vulnerability_count": len(findings),
        "vulnerabilities": findings,
        "warnings": warnings or [],
        "errors": errors or [],
    }


def _finding(
    package_name: str,
    package_version: str,
    vulnerability_id: str,
    *,
    severity: str | None = "HIGH",
    severity_details: list[dict] | None = None,
) -> dict:
    return {
        "package_name": package_name,
        "package_version": package_version,
        "vulnerability_id": vulnerability_id,
        "id": vulnerability_id,
        "summary": f"Summary for {vulnerability_id}",
        "severity": severity,
        "severity_details": severity_details or [],
        "fixed_versions": ["9.9.9"],
    }


def _report(inventory: list[dict], vulnerabilities: list[dict] | None = None):
    return build_risk_report(
        _discovery_result(inventory),
        _vulnerability_result(vulnerabilities),
    )


class FakeOSVClient:
    def __init__(self, *, batch_results=None, details=None, batch_error=None):
        self.batch_results = batch_results or []
        self.details = details or {}
        self.batch_error = batch_error
        self.batch_calls = 0
        self.detail_calls: list[str] = []
        self.queries = []

    def query_batch(self, queries):
        self.batch_calls += 1
        self.queries = queries
        if self.batch_error is not None:
            raise self.batch_error
        return self.batch_results

    def get_vulnerability(self, vulnerability_id):
        self.detail_calls.append(vulnerability_id)
        return self.details[vulnerability_id]


def _patch_discovery(monkeypatch, inventory: list[dict], *, status=STATUS_SUCCESS):
    calls = []

    def fake_discover(project_directory):
        calls.append(project_directory)
        return _discovery_result(inventory, status=status)

    monkeypatch.setattr(risk_analyzer, "discover_dependencies", fake_discover)
    return calls


def test_no_vulnerabilities_produces_low_risk():
    report = _report([_entry("requests", "2.31.0", ["==2.31.0"])])

    assert report["status"] == STATUS_SUCCESS
    assert report["project_risk"] == RISK_LOW
    assert report["overall_risk"] == RISK_LOW
    assert report["summary"]["project_risk"] == RISK_LOW
    assert report["summary"]["total_dependencies"] == 1
    assert report["summary"]["vulnerable_dependency_count"] == 0
    assert report["summary"]["unresolved_dependency_count"] == 0
    assert report["summary"]["incomplete_coverage_dependency_count"] == 0

    dependency = report["dependencies"][0]
    assert dependency["package_name"] == "requests"
    assert dependency["resolved_version"] == "2.31.0"
    assert dependency["risk_classification"] == RISK_LOW
    assert dependency["vulnerability_count"] == 0
    assert dependency["scan_coverage"] == COVERAGE_COMPLETE
    assert dependency["scan_complete"] is True
    assert dependency["declared_constraints"] == ["==2.31.0"]
    assert dependency["reasons"]


@pytest.mark.parametrize(
    ("severity", "expected"),
    [
        ("CRITICAL", RISK_CRITICAL),
        ("HIGH", RISK_HIGH),
        ("MEDIUM", RISK_MEDIUM),
        ("MODERATE", RISK_MEDIUM),
        ("LOW", RISK_LOW),
    ],
)
def test_osv_severity_labels_map_to_risk(severity, expected):
    report = _report(
        [_entry("requests", "2.31.0")],
        [_finding("requests", "2.31.0", "OSV-1", severity=severity)],
    )

    dependency = report["dependencies"][0]
    assert dependency["risk_classification"] == expected
    assert dependency["highest_vulnerability_risk"] == expected
    assert report["project_risk"] == expected
    assert report["summary"]["risk_counts"][expected] == 1


def test_cvss_vector_is_used_when_severity_label_is_missing():
    finding = _finding(
        "requests",
        "2.31.0",
        "OSV-CVSS",
        severity=None,
        severity_details=[
            {
                "type": "CVSS_V3",
                "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            }
        ],
    )

    report = _report([_entry("requests", "2.31.0")], [finding])

    assert report["dependencies"][0]["risk_classification"] == RISK_CRITICAL
    assert report["dependencies"][0]["reasons"]


def test_numeric_cvss_score_is_used():
    finding = _finding(
        "requests",
        "2.31.0",
        "OSV-SCORE",
        severity=None,
        severity_details=[{"type": "CVSS_V3", "score": "7.5"}],
    )

    report = _report([_entry("requests", "2.31.0")], [finding])

    assert report["dependencies"][0]["risk_classification"] == RISK_HIGH


def test_finding_without_usable_severity_is_unknown_not_low():
    finding = _finding(
        "requests",
        "2.31.0",
        "OSV-UNKNOWN",
        severity=None,
        severity_details=[],
    )

    report = _report([_entry("requests", "2.31.0")], [finding])

    dependency = report["dependencies"][0]
    assert dependency["risk_classification"] == RISK_UNKNOWN
    assert "did not provide a usable severity" in dependency["risk_reason"]
    assert report["project_risk"] == RISK_UNKNOWN


def test_multiple_vulnerabilities_use_highest_severity_and_report_count():
    findings = [
        _finding("requests", "2.31.0", "OSV-HIGH", severity="HIGH"),
        _finding("requests", "2.31.0", "OSV-LOW", severity="LOW"),
    ]

    report = _report([_entry("requests", "2.31.0")], findings)

    dependency = report["dependencies"][0]
    assert dependency["risk_classification"] == RISK_HIGH
    assert dependency["vulnerability_count"] == 2
    assert dependency["vulnerability_ids"] == ["OSV-HIGH", "OSV-LOW"]
    assert dependency["severity_breakdown"][RISK_HIGH] == 1
    assert dependency["severity_breakdown"][RISK_LOW] == 1
    assert "2 known vulnerability(ies)" in dependency["risk_reason"]
    assert report["summary"]["vulnerable_dependency_count"] == 1
    assert report["summary"]["risk_counts"][RISK_HIGH] == 1

def test_unresolved_version_is_unknown_and_not_treated_as_safe():
    report = build_risk_report(
        _discovery_result([_entry("requests", constraints=["==2.31.0"])]),
        _vulnerability_result(
            status=STATUS_PARTIAL,
            checked=0,
            eligible=0,
            unresolved=1,
            warnings=["requests: no resolved version"],
        ),
    )

    assert report["status"] == STATUS_PARTIAL
    assert report["project_risk"] == RISK_UNKNOWN
    assert report["summary"]["unresolved_dependency_count"] == 1
    assert report["summary"]["incomplete_coverage_dependency_count"] == 0
    assert report["scan_coverage"] == COVERAGE_UNAVAILABLE

    dependency = report["dependencies"][0]
    assert dependency["version_resolved"] is False
    assert dependency["resolved_version"] is None
    assert dependency["risk_classification"] == RISK_UNKNOWN
    assert dependency["scan_coverage"] == COVERAGE_UNRESOLVED
    assert dependency["scan_complete"] is False
    assert "No explicit resolved version" in dependency["risk_reason"]


def test_invalid_explicit_version_is_not_treated_as_resolved():
    report = build_risk_report(
        _discovery_result([_entry("requests", "not-a-version")]),
        _vulnerability_result(
            status=STATUS_PARTIAL,
            checked=0,
            eligible=0,
            unresolved=1,
            warnings=["requests: invalid version"],
        ),
    )

    dependency = report["dependencies"][0]
    assert dependency["version_resolved"] is False
    assert dependency["resolved_version"] is None
    assert dependency["risk_classification"] == RISK_UNKNOWN
    assert dependency["scan_coverage"] == COVERAGE_UNRESOLVED


def test_partial_scan_without_findings_is_unknown():
    report = build_risk_report(
        _discovery_result([_entry("requests", "2.31.0")]),
        _vulnerability_result(
            status=STATUS_PARTIAL,
            checked=1,
            errors=["OSV detail request failed"],
        ),
    )

    assert report["status"] == STATUS_PARTIAL
    assert report["scan_coverage"] == COVERAGE_PARTIAL
    assert report["project_risk"] == RISK_UNKNOWN
    assert report["summary"]["incomplete_coverage_dependency_count"] == 1

    dependency = report["dependencies"][0]
    assert dependency["risk_classification"] == RISK_UNKNOWN
    assert dependency["scan_coverage"] == COVERAGE_PARTIAL
    assert "incomplete or unavailable" in dependency["risk_reason"]


def test_partial_scan_keeps_known_severity_but_flags_incomplete_coverage():
    report = build_risk_report(
        _discovery_result([_entry("requests", "2.31.0")]),
        _vulnerability_result(
            [_finding("requests", "2.31.0", "OSV-HIGH", severity="HIGH")],
            status=STATUS_PARTIAL,
            checked=1,
            errors=["OSV detail request failed"],
        ),
    )

    dependency = report["dependencies"][0]
    assert dependency["risk_classification"] == RISK_HIGH
    assert dependency["scan_coverage"] == COVERAGE_PARTIAL
    assert "additional vulnerabilities may be missing" in dependency["risk_reason"]
    assert report["project_risk"] == RISK_HIGH
    assert "may be higher" in report["risk_reason"]


def test_osv_timeout_marks_resolved_dependency_coverage_unavailable(monkeypatch):
    _patch_discovery(monkeypatch, [_entry("requests", "2.31.0")])
    client = FakeOSVClient(batch_error=OSVTimeoutError("OSV request timed out"))

    report = analyze_risks("C:/example/project", client=client)

    assert report["status"] == STATUS_PARTIAL
    assert report["scan_coverage"] == COVERAGE_UNAVAILABLE
    assert report["project_risk"] == RISK_UNKNOWN
    assert report["summary"]["incomplete_coverage_dependency_count"] == 1
    assert any("timed out" in error for error in report["errors"])

    dependency = report["dependencies"][0]
    assert dependency["risk_classification"] == RISK_UNKNOWN
    assert dependency["scan_coverage"] == COVERAGE_UNAVAILABLE
    assert client.batch_calls == 1


def test_empty_inventory_returns_empty_status_and_unknown_project_risk():
    report = build_risk_report(
        _discovery_result([]),
        _vulnerability_result(status=STATUS_EMPTY, checked=0, eligible=0),
    )

    assert report["status"] == STATUS_EMPTY
    assert report["total_dependencies"] == 0
    assert report["dependencies"] == []
    assert report["scan_coverage"] == "empty"
    assert report["project_risk"] == RISK_UNKNOWN
    assert report["summary"]["risk_counts"] == {
        RISK_CRITICAL: 0,
        RISK_HIGH: 0,
        RISK_MEDIUM: 0,
        RISK_LOW: 0,
        RISK_UNKNOWN: 0,
    }
    assert "No dependencies" in report["risk_reason"]


def test_invalid_discovery_input_returns_error():
    report = build_risk_report([], {})

    assert report["status"] == STATUS_ERROR
    assert report["project_risk"] == RISK_UNKNOWN
    assert report["dependencies"] == []
    assert report["errors"]
    assert report["error"] == "dependency discovery result must be a dictionary"


def test_discovery_error_returns_error_without_risk_data():
    report = build_risk_report(
        _discovery_result(
            [],
            status=STATUS_ERROR,
            warnings=["project directory does not exist"],
        ),
        {},
    )

    assert report["status"] == STATUS_ERROR
    assert report["source_status"] == STATUS_ERROR
    assert report["dependencies"] == []
    assert report["scan_coverage"] == COVERAGE_UNAVAILABLE
    assert "project directory does not exist" in report["errors"]


def test_project_level_aggregation_surfaces_unknown_and_partial_coverage():
    inventory = [
        _entry("critical-package", "1.0.0"),
        _entry("low-package", "2.0.0"),
        _entry("unresolved-package", constraints=[">=1.0"]),
    ]
    findings = [
        _finding("critical-package", "1.0.0", "OSV-CRIT", severity="CRITICAL"),
        _finding("low-package", "2.0.0", "OSV-LOW", severity="LOW"),
    ]

    report = build_risk_report(
        _discovery_result(inventory),
        _vulnerability_result(
            findings,
            status=STATUS_PARTIAL,
            checked=2,
            eligible=2,
            unresolved=1,
            warnings=["unresolved-package: no resolved version"],
        ),
    )

    assert report["status"] == STATUS_PARTIAL
    assert report["project_risk"] == RISK_CRITICAL
    assert report["summary"]["risk_counts"] == {
        RISK_CRITICAL: 1,
        RISK_HIGH: 0,
        RISK_MEDIUM: 0,
        RISK_LOW: 1,
        RISK_UNKNOWN: 1,
    }
    assert report["summary"]["vulnerable_dependency_count"] == 2
    assert report["summary"]["unresolved_dependency_count"] == 1
    assert report["scan_coverage"] == COVERAGE_PARTIAL
    assert "may be higher" in report["risk_reason"]


def test_dependency_reasons_explain_risk_and_coverage():
    report = _report(
        [_entry("requests", "2.31.0")],
        [_finding("requests", "2.31.0", "OSV-HIGH", severity="HIGH")],
    )

    dependency = report["dependencies"][0]
    assert dependency["reasons"]
    assert dependency["risk_reason"]
    assert dependency["scan_coverage_reason"]
    assert "1 known vulnerability(ies)" in dependency["risk_reason"]
    assert "Highest" not in dependency["risk_reason"]
    assert "highest reported vulnerability risk is High" in dependency["risk_reason"]
    assert "complete OSV scan" in dependency["scan_coverage_reason"]


def test_analyze_risks_accepts_existing_service_results():
    report = analyze_risks(
        _discovery_result([_entry("requests", "2.31.0")]),
        _vulnerability_result(
            [_finding("requests", "2.31.0", "OSV-HIGH", severity="HIGH")]
        ),
    )

    assert report["project_risk"] == RISK_HIGH
    assert report["dependencies"][0]["risk_classification"] == RISK_HIGH


def test_analysis_makes_one_batch_request_and_one_detail_request(monkeypatch):
    _patch_discovery(
        monkeypatch,
        [
            _entry("requests", "2.31.0"),
            _entry("urllib3", "2.0.7"),
        ],
    )
    detail = {
        "id": "OSV-SHARED",
        "summary": "Shared advisory",
        "database_specific": {"severity": "HIGH"},
    }
    client = FakeOSVClient(
        batch_results=[
            {"vulns": [{"id": "OSV-SHARED"}]},
            {"vulns": [{"id": "OSV-SHARED"}]},
        ],
        details={"OSV-SHARED": detail},
    )

    report = analyze_risks("C:/example/project", client=client)

    assert client.batch_calls == 1
    assert len(client.queries) == 2
    assert client.detail_calls == ["OSV-SHARED"]
    assert report["summary"]["total_dependencies"] == 2
    assert report["summary"]["vulnerable_dependency_count"] == 2
