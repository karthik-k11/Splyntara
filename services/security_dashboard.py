"""Dashboard analysis composition.

The dashboard needs discovery, vulnerability findings, risk explanations, and a
report snapshot. This module composes the existing services so a single
analysis performs exactly one discovery and one OSV scan. It does not contain
its own manifest parsing, OSV client, or risk scoring logic.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from services.dependency_discovery import (
    STATUS_ERROR as DISCOVERY_STATUS_ERROR,
    STATUS_NO_MANIFESTS,
    discover_dependencies,
)
from services.risk_analyzer import (
    STATUS_EMPTY as RISK_STATUS_EMPTY,
    STATUS_ERROR as RISK_STATUS_ERROR,
    STATUS_SUCCESS as RISK_STATUS_SUCCESS,
    build_risk_report,
)
from services.security_report import (
    RISK_LEVELS,
    build_security_report,
    merge_risk_dependencies,
)
from services.vulnerability_scanner import build_vulnerability_report

DashboardResult = dict[str, Any]

__all__ = [
    "DashboardResult",
    "analyze_security_dashboard",
    "build_dashboard_error",
]


def analyze_security_dashboard(
    project_directory: str | Path,
    *,
    client: Any = None,
) -> DashboardResult:
    """Run one discovery, one OSV scan, and build dashboard + report data."""
    discovery = discover_dependencies(project_directory)
    discovery_status = _text(discovery.get("status"))
    project_directory_text = _text(discovery.get("project_directory"))
    project_name = _text(discovery.get("project_name")) or _project_name(
        project_directory_text
    )

    if discovery_status == DISCOVERY_STATUS_ERROR:
        warnings = _string_list(discovery.get("warnings"))
        message = warnings[0] if warnings else "dependency discovery failed"
        return build_dashboard_error(
            message,
            project_directory=project_directory_text,
            project_name=project_name,
            warnings=warnings,
        )

    vulnerability = build_vulnerability_report(discovery, client=client)
    risk = build_risk_report(discovery, vulnerability)
    risk_status = _text(risk.get("status"))

    if risk_status == RISK_STATUS_ERROR:
        warnings = _dedupe(
            _string_list(discovery.get("warnings"))
            + _string_list(vulnerability.get("warnings"))
            + _string_list(risk.get("warnings"))
        )
        errors = _dedupe(
            _string_list(vulnerability.get("errors"))
            + _string_list(risk.get("errors"))
        )
        message = errors[0] if errors else (
            warnings[0] if warnings else "risk analysis failed"
        )
        return build_dashboard_error(
            message,
            project_directory=project_directory_text,
            project_name=project_name,
            warnings=warnings,
            errors=errors,
        )

    report = build_security_report(discovery, vulnerability, risk)
    dependencies = merge_risk_dependencies(discovery, risk)
    warnings = _dedupe(
        _string_list(discovery.get("warnings"))
        + _string_list(vulnerability.get("warnings"))
        + _string_list(risk.get("warnings"))
    )
    errors = _dedupe(
        _string_list(vulnerability.get("errors"))
        + _string_list(risk.get("errors"))
    )

    if risk_status == RISK_STATUS_EMPTY or discovery_status == STATUS_NO_MANIFESTS:
        status = "empty"
    elif (
        risk_status == RISK_STATUS_SUCCESS
        and discovery_status == "success"
        and not warnings
        and not errors
    ):
        status = "success"
    else:
        status = "partial"

    return {
        "status": status,
        "project": {
            "name": project_name,
            "directory": project_directory_text,
            "discovery_status": discovery_status,
            "manifests": report["project"]["manifests"],
            "manifest_count": len(report["project"]["manifests"]),
        },
        "summary": report["scan_summary"],
        "dependencies": dependencies,
        "vulnerabilities": _dict_list(vulnerability.get("vulnerabilities")),
        "risk": risk,
        "report": report,
        "warnings": warnings,
        "errors": errors,
    }


def build_dashboard_error(
    message: str,
    *,
    project_directory: str = "",
    project_name: str = "",
    warnings: list[str] | None = None,
    errors: list[str] | None = None,
) -> DashboardResult:
    """Build a stable dashboard error payload."""
    message = message or "analysis failed"
    combined_warnings = _dedupe([message] + list(warnings or []))
    combined_errors = _dedupe([message] + list(errors or []))
    risk_counts = {level: 0 for level in RISK_LEVELS}

    summary = {
        "total_dependencies": 0,
        "vulnerable_dependencies": 0,
        "total_vulnerabilities": 0,
        "risk_counts": risk_counts,
        "unknown_risk_dependencies": 0,
        "unresolved_dependencies": 0,
        "incomplete_coverage_dependencies": 0,
        "project_risk": "Unknown",
        "risk_reason": message,
        "scan_coverage": "unavailable",
        "scan_status": "error",
        "source_status": "error",
        "dependencies_checked": 0,
        "eligible_dependencies": 0,
    }

    return {
        "status": "error",
        "error": message,
        "project": {
            "name": project_name,
            "directory": project_directory,
            "discovery_status": "error",
            "manifests": [],
            "manifest_count": 0,
        },
        "summary": summary,
        "dependencies": [],
        "vulnerabilities": [],
        "risk": None,
        "report": None,
        "warnings": combined_warnings,
        "errors": combined_errors,
    }


def _project_name(project_directory: str) -> str:
    if not project_directory:
        return ""
    return Path(project_directory).name


def _dict_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, list):
        values = value
    else:
        return []

    return [
        item.strip()
        for item in values
        if isinstance(item, str) and item.strip()
    ]


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result
