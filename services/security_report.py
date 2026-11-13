"""Security report assembly for the Splyntara dashboard.

This module is deliberately presentation-oriented. It consumes the existing
dependency discovery, vulnerability scan, and risk analysis results. It does not
parse manifests, query OSV, or generate SBOMs, and it does not change any risk
classification.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from services.manifest_parsers import normalize_package_name

RISK_LEVELS = ("Critical", "High", "Medium", "Low", "Unknown")

REPORT_FORMAT = "splyntara.security-report"
REPORT_VERSION = 1

LIMITATIONS = (
    "Resolved versions must be supplied explicitly. Manifest declarations, "
    "version ranges, and exact manifest pins are not treated as resolved "
    "versions.",
    "OSV coverage is limited to dependencies that have an explicit resolved "
    "version. Unresolved dependencies are reported as Unknown risk.",
    "Risk reflects known OSV advisories and documented severity information "
    "only. EPSS, exploitability, transitive dependency graphs, and proprietary "
    "feeds are not used.",
    "The report is a point-in-time snapshot and is not persisted by Splyntara.",
)

_SEVERITY_LABELS = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "MODERATE": "Medium",
    "LOW": "Low",
    "NONE": "Unknown",
    "UNKNOWN": "Unknown",
}

Report = dict[str, Any]

__all__ = [
    "RISK_LEVELS",
    "REPORT_FORMAT",
    "REPORT_VERSION",
    "LIMITATIONS",
    "Report",
    "build_security_report",
    "merge_risk_dependencies",
]


def build_security_report(
    discovery_result: Any,
    vulnerability_result: Any,
    risk_result: Any,
    *,
    generated_at: str | None = None,
) -> Report:
    """Build a complete, exportable security report from existing results."""
    discovery = discovery_result if isinstance(discovery_result, dict) else {}
    vulnerability = vulnerability_result if isinstance(vulnerability_result, dict) else {}
    risk = risk_result if isinstance(risk_result, dict) else {}

    project_directory = _text(discovery.get("project_directory"))
    project_name = _text(discovery.get("project_name")) or _project_name(
        project_directory
    )

    risk_counts = _risk_counts(risk.get("risk_counts"))
    summary = _scan_summary(
        discovery=discovery,
        vulnerability=vulnerability,
        risk=risk,
        risk_counts=risk_counts,
    )
    dependencies = merge_risk_dependencies(discovery, risk)
    inventory = [_inventory_entry(item) for item in dependencies]
    findings = [
        _finding_entry(item)
        for item in _dict_list(vulnerability.get("vulnerabilities"))
    ]

    warnings = _dedupe(
        _string_list(discovery.get("warnings"))
        + _string_list(vulnerability.get("warnings"))
        + _string_list(risk.get("warnings"))
    )
    errors = _dedupe(
        _string_list(vulnerability.get("errors"))
        + _string_list(risk.get("errors"))
    )

    report = {
        "format": REPORT_FORMAT,
        "version": REPORT_VERSION,
        "generated_at": generated_at or _timestamp(),
        "project": {
            "name": project_name,
            "directory": project_directory,
            "discovery_status": _text(discovery.get("status")) or "unknown",
            "manifests": [_manifest_entry(item) for item in _dict_list(
                discovery.get("manifests")
            )],
        },
        "scan_summary": summary,
        "summary": summary,
        "inventory": inventory,
        "vulnerabilities": findings,
        "risk": {
            "project_risk": summary["project_risk"],
            "risk_reason": summary["risk_reason"],
            "risk_counts": risk_counts,
            "dependencies": [
                {
                    "package_name": item.get("package_name"),
                    "resolved_version": item.get("resolved_version"),
                    "risk": item.get("risk_classification") or "Unknown",
                    "risk_reason": item.get("risk_reason") or "",
                    "reasons": _string_list(item.get("reasons")),
                    "scan_coverage": item.get("scan_coverage"),
                    "vulnerability_count": _int_or_zero(
                        item.get("vulnerability_count")
                    ),
                    "vulnerability_ids": _string_list(
                        item.get("vulnerability_ids")
                    ),
                    "fixed_versions": _string_list(item.get("fixed_versions")),
                }
                for item in dependencies
            ],
        },
        "coverage": {
            "status": summary["scan_coverage"],
            "scan_status": summary["scan_status"],
            "dependencies_checked": summary["dependencies_checked"],
            "eligible_dependencies": summary["eligible_dependencies"],
            "unresolved_dependencies": summary["unresolved_dependencies"],
            "incomplete_coverage_dependencies": summary[
                "incomplete_coverage_dependencies"
            ],
            "vulnerable_dependencies": summary["vulnerable_dependencies"],
            "notes": _coverage_notes(summary),
        },
        "warnings": warnings,
        "errors": errors,
        "limitations": list(LIMITATIONS),
    }

    return report


def merge_risk_dependencies(
    discovery_result: Any,
    risk_result: Any,
) -> list[dict[str, Any]]:
    """Merge risk dependency entries with discovery manifest metadata.

    The risk analyzer owns classification and reasons. Discovery owns the
    manifest references. This helper only joins those existing facts.
    """
    discovery = discovery_result if isinstance(discovery_result, dict) else {}
    risk = risk_result if isinstance(risk_result, dict) else {}

    inventory_by_name: dict[str, dict[str, Any]] = {}
    for entry in _dict_list(discovery.get("inventory")):
        package_name = _package_name(entry)
        if package_name is not None:
            inventory_by_name[package_name] = entry

    merged: list[dict[str, Any]] = []
    for entry in _dict_list(risk.get("dependencies")):
        package_name = _package_name(entry)
        if package_name is None:
            continue

        dependency = dict(entry)
        inventory_entry = inventory_by_name.get(package_name, {})
        sources = _string_list(inventory_entry.get("source_manifests"))

        if not sources:
            for declaration in _dict_list(inventory_entry.get("declarations")):
                source = _text(declaration.get("source_manifest"))
                if source:
                    sources.append(source)

        dependency["package_name"] = package_name
        dependency["manifest_sources"] = _dedupe(sources)
        dependency["dependency_types"] = _string_list(
            inventory_entry.get("dependency_types")
        )
        dependency["optional_groups"] = _string_list(
            inventory_entry.get("optional_groups")
        )
        merged.append(dependency)

    return merged


def _scan_summary(
    *,
    discovery: dict[str, Any],
    vulnerability: dict[str, Any],
    risk: dict[str, Any],
    risk_counts: dict[str, int],
) -> dict[str, Any]:
    risk_summary = risk.get("summary")
    if not isinstance(risk_summary, dict):
        risk_summary = {}

    total_dependencies = _int_or_zero(
        risk.get("total_dependencies", risk_summary.get("total_dependencies"))
    )
    vulnerable_dependencies = _int_or_zero(
        risk.get(
            "vulnerable_dependency_count",
            risk_summary.get("vulnerable_dependency_count"),
        )
    )
    unresolved_dependencies = _int_or_zero(
        risk.get(
            "unresolved_dependency_count",
            risk_summary.get("unresolved_dependency_count"),
        )
    )
    incomplete_coverage = _int_or_zero(
        risk.get(
            "incomplete_coverage_dependency_count",
            risk_summary.get("incomplete_coverage_dependency_count"),
        )
    )
    project_risk = (
        _text(risk.get("project_risk"))
        or _text(risk_summary.get("project_risk"))
        or "Unknown"
    )
    scan_coverage = (
        _text(risk.get("scan_coverage"))
        or _text(risk_summary.get("scan_coverage"))
        or "unavailable"
    )
    scan_status = (
        _text(risk.get("scan_status"))
        or _text(risk_summary.get("scan_status"))
        or _text(vulnerability.get("status"))
        or "unknown"
    )

    return {
        "total_dependencies": total_dependencies,
        "vulnerable_dependencies": vulnerable_dependencies,
        "total_vulnerabilities": _int_or_zero(
            vulnerability.get("total_vulnerability_count")
        ),
        "risk_counts": risk_counts,
        "unknown_risk_dependencies": risk_counts.get("Unknown", 0),
        "unresolved_dependencies": unresolved_dependencies,
        "incomplete_coverage_dependencies": incomplete_coverage,
        "project_risk": project_risk,
        "risk_reason": _text(risk.get("risk_reason"))
        or _text(risk_summary.get("risk_reason")),
        "scan_coverage": scan_coverage,
        "scan_status": scan_status,
        "source_status": _text(discovery.get("status")) or "unknown",
        "dependencies_checked": _int_or_zero(
            vulnerability.get("total_dependencies_checked")
        ),
        "eligible_dependencies": _int_or_zero(
            vulnerability.get("eligible_dependency_count")
        ),
    }


def _inventory_entry(dependency: dict[str, Any]) -> dict[str, Any]:
    return {
        "package_name": dependency.get("package_name"),
        "name": dependency.get("name") or dependency.get("package_name"),
        "declared_constraints": _string_list(
            dependency.get("declared_constraints")
        ),
        "resolved_version": dependency.get("resolved_version"),
        "version_resolved": bool(dependency.get("version_resolved")),
        "manifest_sources": _string_list(
            dependency.get("manifest_sources")
        ),
        "dependency_types": _string_list(dependency.get("dependency_types")),
        "risk": dependency.get("risk_classification") or "Unknown",
        "risk_reason": dependency.get("risk_reason") or "",
        "vulnerability_count": _int_or_zero(
            dependency.get("vulnerability_count")
        ),
        "vulnerability_ids": _string_list(dependency.get("vulnerability_ids")),
        "fixed_versions": _string_list(dependency.get("fixed_versions")),
        "scan_coverage": dependency.get("scan_coverage"),
    }


def _finding_entry(finding: dict[str, Any]) -> dict[str, Any]:
    severity = _text(finding.get("severity"))
    references = []
    for reference in _dict_list(finding.get("references")):
        url = _http_url(reference.get("url"))
        if url is not None:
            references.append({
                "type": reference.get("type"),
                "url": url,
            })

    return {
        "package_name": finding.get("package_name"),
        "package_version": finding.get("package_version"),
        "vulnerability_id": finding.get("vulnerability_id")
        or finding.get("id"),
        "aliases": _string_list(finding.get("aliases")),
        "severity": severity,
        "severity_label": _severity_label(severity),
        "summary": finding.get("summary"),
        "details": finding.get("details"),
        "fixed_versions": _string_list(finding.get("fixed_versions")),
        "references": references,
        "published": finding.get("published"),
        "modified": finding.get("modified"),
    }


def _manifest_entry(manifest: dict[str, Any]) -> dict[str, Any]:
    return {
        "filename": manifest.get("filename"),
        "format": manifest.get("format"),
        "status": manifest.get("status"),
        "dependency_count": _int_or_zero(manifest.get("dependency_count")),
    }


def _coverage_notes(summary: dict[str, Any]) -> list[str]:
    notes: list[str] = []
    unresolved = summary["unresolved_dependencies"]
    incomplete = summary["incomplete_coverage_dependencies"]
    coverage = summary["scan_coverage"]

    if unresolved:
        notes.append(
            f"{unresolved} dependency(ies) have no explicit resolved version and "
            "were excluded from OSV scanning."
        )

    if incomplete:
        notes.append(
            f"{incomplete} resolved dependency(ies) did not receive complete OSV "
            "coverage."
        )

    if coverage == "complete":
        notes.append(
            "Every resolved dependency was checked by a complete OSV scan."
        )
    elif coverage == "partial":
        notes.append(
            "OSV coverage is partial. Absence of a finding does not prove that a "
            "dependency is safe."
        )
    elif coverage == "unavailable":
        notes.append(
            "No successful OSV coverage was available for the resolved "
            "dependencies."
        )
    elif coverage == "empty":
        notes.append("No dependencies were available to scan.")
    elif coverage == "unresolved":
        notes.append(
            "Dependencies could not be scanned because no resolved versions were "
            "available."
        )

    if summary["total_dependencies"] == 0:
        notes.append("No Python manifests or dependency declarations were found.")

    return notes


def _risk_counts(value: Any) -> dict[str, int]:
    source = value if isinstance(value, dict) else {}
    return {level: _int_or_zero(source.get(level)) for level in RISK_LEVELS}


def _package_name(entry: dict[str, Any]) -> str | None:
    value = entry.get("normalized_name", entry.get("package_name", entry.get("name")))
    if not isinstance(value, str) or not value.strip():
        return None
    return normalize_package_name(value.strip()) or None


def _project_name(project_directory: str) -> str:
    if not project_directory:
        return ""
    return Path(project_directory).name


def _severity_label(value: str) -> str:
    if not value:
        return "Unknown"

    label = _SEVERITY_LABELS.get(value.strip().upper())
    if label is not None:
        return label

    try:
        score = float(value)
    except (TypeError, ValueError):
        return "Unknown"

    if score <= 0:
        return "Unknown"
    return f"CVSS {value}"


def _http_url(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None

    candidate = value.strip()
    try:
        parsed = urlparse(candidate)
    except ValueError:
        return None

    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        return None

    return candidate


def _timestamp() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


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


def _int_or_zero(value: Any) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return max(value, 0)
    if isinstance(value, float) and value.is_integer():
        return max(int(value), 0)
    return 0


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result
