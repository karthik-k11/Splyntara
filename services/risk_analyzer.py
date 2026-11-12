"""Explainable dependency risk analysis.

The analyzer combines the existing dependency discovery inventory with the
existing OSV vulnerability scan result. It does not parse manifests, query OSV,
or generate SBOMs itself. One analysis operation performs one discovery and one
vulnerability scan, so the same OSV work is not repeated.

Risk is based only on evidence that is available: explicit resolved versions,
OSV findings, OSV severity labels, and documented CVSS v2/v3 scores or vectors.
Missing evidence is reported as ``Unknown``; it is never silently treated as
low risk.
"""

from __future__ import annotations

import math
import re
from pathlib import Path
from typing import Any

from packaging.version import InvalidVersion, Version

from services.dependency_discovery import (
    STATUS_ERROR as DISCOVERY_STATUS_ERROR,
    STATUS_PARTIAL as DISCOVERY_STATUS_PARTIAL,
    discover_dependencies,
)
from services.manifest_parsers import normalize_package_name
from services.vulnerability_scanner import (
    STATUS_EMPTY as VULNERABILITY_STATUS_EMPTY,
    STATUS_ERROR as VULNERABILITY_STATUS_ERROR,
    STATUS_PARTIAL as VULNERABILITY_STATUS_PARTIAL,
    STATUS_SUCCESS as VULNERABILITY_STATUS_SUCCESS,
    build_vulnerability_report,
)

RISK_CRITICAL = "Critical"
RISK_HIGH = "High"
RISK_MEDIUM = "Medium"
RISK_LOW = "Low"
RISK_UNKNOWN = "Unknown"

RISK_LEVELS = (
    RISK_CRITICAL,
    RISK_HIGH,
    RISK_MEDIUM,
    RISK_LOW,
    RISK_UNKNOWN,
)

COVERAGE_COMPLETE = "complete"
COVERAGE_PARTIAL = "partial"
COVERAGE_UNAVAILABLE = "unavailable"
COVERAGE_UNRESOLVED = "unresolved"
COVERAGE_EMPTY = "empty"

STATUS_SUCCESS = "success"
STATUS_PARTIAL = "partial"
STATUS_EMPTY = "empty"
STATUS_ERROR = "error"

_RISK_RANK = {
    RISK_CRITICAL: 5,
    RISK_HIGH: 4,
    RISK_MEDIUM: 3,
    RISK_LOW: 2,
    RISK_UNKNOWN: 1,
}

_SEVERITY_LABELS = {
    "CRITICAL": RISK_CRITICAL,
    "HIGH": RISK_HIGH,
    "MEDIUM": RISK_MEDIUM,
    "MODERATE": RISK_MEDIUM,
    "LOW": RISK_LOW,
    "UNKNOWN": RISK_UNKNOWN,
    "NONE": RISK_UNKNOWN,
}

_NUMERIC_SCORE = re.compile(r"^\d+(?:\.\d+)?$")

RiskAnalysisResult = dict[str, Any]

__all__ = [
    "RISK_CRITICAL",
    "RISK_HIGH",
    "RISK_MEDIUM",
    "RISK_LOW",
    "RISK_UNKNOWN",
    "RISK_LEVELS",
    "COVERAGE_COMPLETE",
    "COVERAGE_PARTIAL",
    "COVERAGE_UNAVAILABLE",
    "COVERAGE_UNRESOLVED",
    "COVERAGE_EMPTY",
    "STATUS_SUCCESS",
    "STATUS_PARTIAL",
    "STATUS_EMPTY",
    "STATUS_ERROR",
    "RiskAnalysisResult",
    "analyze_risks",
    "analyze_project_risks",
    "build_risk_report",
]


def analyze_risks(
    project_directory: str | Path | dict[str, Any],
    vulnerability_result: Any = None,
    *,
    client: Any = None,
) -> RiskAnalysisResult:
    """Run discovery plus one vulnerability scan, then analyze the result.

    The first argument may also be an existing discovery result. In that case,
    callers can pass an existing vulnerability scan result as the second
    argument, or let this function scan the discovery result once.

    ``client`` is forwarded to the existing vulnerability scanner. It is mostly
    useful for tests; production callers can omit it.
    """

    if isinstance(project_directory, dict):
        discovery_result = project_directory
        if vulnerability_result is None:
            vulnerability_result = build_vulnerability_report(
                discovery_result,
                client=client,
            )
        return build_risk_report(discovery_result, vulnerability_result)

    discovery_result = discover_dependencies(project_directory)
    vulnerability_result = build_vulnerability_report(
        discovery_result,
        client=client,
    )
    return build_risk_report(discovery_result, vulnerability_result)


def analyze_project_risks(
    project_directory: str | Path | dict[str, Any],
    vulnerability_result: Any = None,
    *,
    client: Any = None,
) -> RiskAnalysisResult:
    """Alias for :func:`analyze_risks` with an explicit project-oriented name."""

    return analyze_risks(
        project_directory,
        vulnerability_result,
        client=client,
    )


def build_risk_report(
    discovery_result: Any,
    vulnerability_result: Any,
) -> RiskAnalysisResult:
    """Build an explainable risk report from existing service results."""

    if not isinstance(discovery_result, dict):
        return _error_result("dependency discovery result must be a dictionary")

    project_directory = _text(discovery_result.get("project_directory"))
    project_name = _text(discovery_result.get("project_name"))
    source_status = _text(discovery_result.get("status")) or STATUS_ERROR
    discovery_warnings = _string_list(discovery_result.get("warnings"))

    if source_status == DISCOVERY_STATUS_ERROR:
        message = (
            discovery_warnings[0]
            if discovery_warnings
            else "dependency discovery failed"
        )
        return _error_result(
            message,
            project_directory=project_directory,
            project_name=project_name,
            warnings=discovery_warnings,
            errors=[message],
        )

    if not isinstance(vulnerability_result, dict):
        message = "vulnerability scan result must be a dictionary"
        return _error_result(
            message,
            project_directory=project_directory,
            project_name=project_name,
            warnings=discovery_warnings,
            errors=[message],
        )

    scan_status = (
        _text(vulnerability_result.get("status")) or VULNERABILITY_STATUS_ERROR
    )
    scan_warnings = _string_list(vulnerability_result.get("warnings"))
    scan_errors = _string_list(vulnerability_result.get("errors"))
    warnings = _dedupe(discovery_warnings + scan_warnings)
    errors = _dedupe(scan_errors)

    if scan_status == VULNERABILITY_STATUS_ERROR:
        message = errors[0] if errors else "vulnerability scan failed"
        return _error_result(
            message,
            project_directory=project_directory,
            project_name=project_name,
            warnings=warnings,
            errors=errors or [message],
        )

    inventory = discovery_result.get("inventory")
    if not isinstance(inventory, list):
        if inventory is not None:
            warnings.append("inventory is not a list; no dependencies were analyzed")
        inventory = []

    findings_by_package, finding_warnings = _index_vulnerabilities(
        vulnerability_result.get("vulnerabilities")
    )
    warnings = _dedupe(warnings + finding_warnings)

    checked_count = _int_or_zero(
        vulnerability_result.get("total_dependencies_checked")
    )
    scan_has_errors = bool(errors)

    dependencies: list[dict[str, Any]] = []

    for index, entry in enumerate(inventory):
        if not isinstance(entry, dict):
            warnings.append(
                f"inventory entry {index} is not an object and was skipped"
            )
            continue

        package_name = _normalized_package_name(entry)
        if package_name is None:
            warnings.append(
                f"inventory entry {index} has no package name and was skipped"
            )
            continue

        display_name = _display_name(entry, package_name)
        constraints = _declared_constraints(entry)
        resolved_version = _resolved_version(entry)
        findings = (
            findings_by_package.get((package_name, resolved_version), [])
            if resolved_version is not None
            else []
        )

        coverage, coverage_reason, scan_complete = _dependency_coverage(
            resolved_version=resolved_version,
            scan_status=scan_status,
            checked_count=checked_count,
            scan_has_errors=scan_has_errors,
        )
        risk, reasons = _dependency_risk(
            package_name=package_name,
            resolved_version=resolved_version,
            findings=findings,
            coverage=coverage,
            scan_complete=scan_complete,
        )

        severity_breakdown = {level: 0 for level in RISK_LEVELS}
        for finding in findings:
            severity_breakdown[_finding_risk(finding)] += 1

        vulnerability_ids = _vulnerability_ids(findings)
        highest_vulnerability_risk = _highest_risk(
            [_finding_risk(finding) for finding in findings]
        )

        dependencies.append(
            {
                "package_name": package_name,
                "name": display_name,
                "display_name": display_name,
                "resolved_version": resolved_version,
                "version": resolved_version,
                "version_resolved": resolved_version is not None,
                "declared_constraints": constraints,
                "version_constraints": constraints,
                "risk": risk,
                "risk_classification": risk,
                "risk_reason": " ".join(reasons),
                "reasons": reasons,
                "is_vulnerable": bool(findings),
                "vulnerability_count": len(findings),
                "vulnerability_ids": vulnerability_ids,
                "highest_vulnerability_risk": highest_vulnerability_risk,
                "severity_breakdown": severity_breakdown,
                "fixed_versions": _fixed_versions(findings),
                "scan_coverage": coverage,
                "scan_coverage_reason": coverage_reason,
                "coverage_reason": coverage_reason,
                "scan_complete": scan_complete,
                "vulnerabilities": findings,
            }
        )

    total_dependencies = len(dependencies)
    risk_counts = {level: 0 for level in RISK_LEVELS}
    for dependency in dependencies:
        risk_counts[dependency["risk_classification"]] += 1

    vulnerable_dependency_count = sum(
        1 for dependency in dependencies if dependency["is_vulnerable"]
    )
    unresolved_dependency_count = sum(
        1 for dependency in dependencies if not dependency["version_resolved"]
    )
    incomplete_coverage_dependency_count = sum(
        1
        for dependency in dependencies
        if dependency["version_resolved"] and not dependency["scan_complete"]
    )

    resolved_count = total_dependencies - unresolved_dependency_count

    if total_dependencies == 0:
        scan_coverage = COVERAGE_EMPTY
    elif resolved_count == 0:
        scan_coverage = COVERAGE_UNAVAILABLE
    elif (
        incomplete_coverage_dependency_count == resolved_count
        and checked_count == 0
    ):
        scan_coverage = COVERAGE_UNAVAILABLE
    elif (
        unresolved_dependency_count
        or incomplete_coverage_dependency_count
        or scan_has_errors
        or scan_status != VULNERABILITY_STATUS_SUCCESS
    ):
        scan_coverage = COVERAGE_PARTIAL
    else:
        scan_coverage = COVERAGE_COMPLETE

    highest_known_risk = _highest_risk(
        [
            dependency["risk_classification"]
            for dependency in dependencies
            if dependency["risk_classification"] != RISK_UNKNOWN
        ]
    )
    unknown_count = risk_counts[RISK_UNKNOWN]

    if total_dependencies == 0:
        project_risk = RISK_UNKNOWN
        project_risk_reason = "No dependencies were available for analysis."
    elif highest_known_risk in (RISK_CRITICAL, RISK_HIGH, RISK_MEDIUM):
        project_risk = highest_known_risk
        project_risk_reason = (
            f"Project risk is {project_risk} because at least one dependency is "
            f"classified {project_risk}."
        )
        if (
            unknown_count
            or incomplete_coverage_dependency_count
            or scan_coverage != COVERAGE_COMPLETE
        ):
            project_risk_reason += (
                " Unresolved versions or incomplete coverage remain for other "
                "dependencies, so the project risk may be higher than the highest "
                "known finding."
            )
    elif (
        highest_known_risk == RISK_LOW
        and unknown_count == 0
        and scan_coverage == COVERAGE_COMPLETE
    ):
        project_risk = RISK_LOW
        project_risk_reason = (
            "All analyzed dependencies have complete OSV coverage and no known "
            "vulnerabilities or only Low-severity findings."
        )
    else:
        project_risk = RISK_UNKNOWN
        if highest_known_risk == RISK_LOW:
            project_risk_reason = (
                "The highest known dependency risk is Low, but unresolved versions "
                "or incomplete coverage prevent a project-level Low classification."
            )
        else:
            project_risk_reason = (
                "No dependency could be assigned a known risk classification because "
                "versions are unresolved or OSV coverage is incomplete or unavailable."
            )

    if total_dependencies == 0:
        status = STATUS_EMPTY
    elif (
        scan_status == VULNERABILITY_STATUS_SUCCESS
        and scan_coverage == COVERAGE_COMPLETE
        and source_status != DISCOVERY_STATUS_PARTIAL
    ):
        status = STATUS_SUCCESS
    else:
        status = STATUS_PARTIAL

    summary = {
        "total_dependencies": total_dependencies,
        "risk_counts": risk_counts,
        "vulnerable_dependency_count": vulnerable_dependency_count,
        "unresolved_dependency_count": unresolved_dependency_count,
        "incomplete_coverage_dependency_count": incomplete_coverage_dependency_count,
        "project_risk": project_risk,
        "risk_reason": project_risk_reason,
        "scan_status": scan_status,
        "scan_coverage": scan_coverage,
    }

    return {
        "status": status,
        "source_status": source_status,
        "project_directory": project_directory,
        "project_name": project_name,
        "summary": summary,
        # Convenience aliases keep the response easy to consume while the
        # nested summary remains the canonical project-level view.
        "project_risk": project_risk,
        "overall_risk": project_risk,
        "risk_counts": risk_counts,
        "total_dependencies": total_dependencies,
        "vulnerable_dependency_count": vulnerable_dependency_count,
        "unresolved_dependency_count": unresolved_dependency_count,
        "incomplete_coverage_dependency_count": incomplete_coverage_dependency_count,
        "scan_status": scan_status,
        "scan_coverage": scan_coverage,
        "risk_reason": project_risk_reason,
        "dependencies": dependencies,
        "warnings": warnings,
        "errors": errors,
    }


def _dependency_coverage(
    *,
    resolved_version: str | None,
    scan_status: str,
    checked_count: int,
    scan_has_errors: bool,
) -> tuple[str, str, bool]:
    if resolved_version is None:
        return (
            COVERAGE_UNRESOLVED,
            "No explicit resolved version is available; the dependency was not "
            "eligible for OSV scanning.",
            False,
        )

    if scan_status in (VULNERABILITY_STATUS_ERROR, VULNERABILITY_STATUS_EMPTY):
        return (
            COVERAGE_UNAVAILABLE,
            "The OSV scan did not produce usable coverage for this dependency.",
            False,
        )

    if checked_count <= 0 and scan_status != VULNERABILITY_STATUS_SUCCESS:
        return (
            COVERAGE_UNAVAILABLE,
            "No successful OSV dependency check was recorded.",
            False,
        )

    if scan_has_errors:
        return (
            COVERAGE_PARTIAL,
            "The OSV scan reported errors, so vulnerability findings may be "
            "incomplete.",
            False,
        )

    if scan_status == VULNERABILITY_STATUS_PARTIAL:
        return (
            COVERAGE_COMPLETE,
            "The dependency was checked by OSV; the overall scan was partial "
            "because of other dependencies or warnings.",
            True,
        )

    return (
        COVERAGE_COMPLETE,
        "The dependency was checked by a complete OSV scan.",
        True,
    )


def _dependency_risk(
    *,
    package_name: str,
    resolved_version: str | None,
    findings: list[dict[str, Any]],
    coverage: str,
    scan_complete: bool,
) -> tuple[str, list[str]]:
    label = (
        f"{package_name} {resolved_version}"
        if resolved_version is not None
        else package_name
    )

    if resolved_version is None:
        return (
            RISK_UNKNOWN,
            [
                "No explicit resolved version is available.",
                "The dependency was excluded from the OSV scan, so its vulnerability "
                "risk is unknown.",
            ],
        )

    if findings:
        finding_risks = [_finding_risk(finding) for finding in findings]
        highest = _highest_risk(
            [risk for risk in finding_risks if risk != RISK_UNKNOWN]
        )
        reasons = [
            f"{len(findings)} known vulnerability(ies) affect {label}."
        ]

        if highest is not None:
            reasons.append(
                f"The highest reported vulnerability risk is {highest}."
            )
        else:
            reasons.append(
                "OSV did not provide a usable severity for the reported "
                "vulnerabilities."
            )

        if not scan_complete:
            reasons.append(
                f"Scan coverage is {coverage}; additional vulnerabilities may be "
                "missing."
            )

        return highest if highest is not None else RISK_UNKNOWN, reasons

    if scan_complete and coverage == COVERAGE_COMPLETE:
        return (
            RISK_LOW,
            [
                f"No known vulnerabilities were reported for {label} by a complete "
                "OSV scan."
            ],
        )

    return (
        RISK_UNKNOWN,
        [
            f"No vulnerabilities were reported for {label}, but scan coverage is "
            f"{coverage}.",
            "Risk cannot be determined from incomplete or unavailable scan results.",
        ],
    )


def _index_vulnerabilities(
    value: Any,
) -> tuple[dict[tuple[str, str], list[dict[str, Any]]], list[str]]:
    warnings: list[str] = []
    if value is None:
        return {}, warnings

    if not isinstance(value, list):
        return {}, ["vulnerability findings are not a list; no findings were used"]

    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for index, finding in enumerate(value):
        if not isinstance(finding, dict):
            warnings.append(f"vulnerability finding {index} is not an object")
            continue

        package_name = finding.get("package_name", finding.get("name"))
        package_version = finding.get(
            "package_version",
            finding.get("version"),
        )

        if not isinstance(package_name, str) or not package_name.strip():
            warnings.append(
                f"vulnerability finding {index} has no package name"
            )
            continue

        if not isinstance(package_version, str) or not package_version.strip():
            warnings.append(
                f"vulnerability finding {index} has no package version"
            )
            continue

        key = (
            normalize_package_name(package_name.strip()),
            package_version.strip(),
        )
        grouped.setdefault(key, []).append(finding)

    return grouped, warnings


def _finding_risk(finding: dict[str, Any]) -> str:
    candidates: list[str] = []

    for value in (
        finding.get("severity"),
        finding.get("cvss_score"),
        finding.get("score"),
    ):
        risk = _risk_from_severity_value(value)
        if risk is not None:
            candidates.append(risk)

    details = finding.get("severity_details")
    if isinstance(details, list):
        for detail in details:
            if not isinstance(detail, dict):
                continue
            risk = _risk_from_severity_detail(detail)
            if risk is not None:
                candidates.append(risk)

    known = [risk for risk in candidates if risk != RISK_UNKNOWN]
    if known:
        return max(known, key=lambda risk: _RISK_RANK[risk])
    return RISK_UNKNOWN


def _risk_from_severity_detail(detail: dict[str, Any]) -> str | None:
    score = detail.get("score")
    risk = _risk_from_severity_value(score)
    if risk is None:
        return None

    score_type = detail.get("type")
    if (
        isinstance(score, str)
        and _NUMERIC_SCORE.match(score.strip())
        and isinstance(score_type, str)
        and score_type.strip().upper() == "CVSS_V2"
    ):
        return _classify_cvss_score(float(score), cvss_version=2)

    return risk


def _risk_from_severity_value(value: Any) -> str | None:
    if value is None:
        return None

    if isinstance(value, bool):
        return None

    if isinstance(value, (int, float)):
        return _classify_cvss_score(float(value))

    if not isinstance(value, str):
        return None

    text = value.strip()
    if not text:
        return None

    label = _SEVERITY_LABELS.get(text.upper())
    if label is not None:
        return label

    if _NUMERIC_SCORE.match(text):
        return _classify_cvss_score(float(text))

    score = _cvss3_base_score(text)
    if score is not None:
        return _classify_cvss_score(score)

    score = _cvss2_base_score(text)
    if score is not None:
        return _classify_cvss_score(score, cvss_version=2)

    return None


def _classify_cvss_score(score: float, *, cvss_version: int = 3) -> str:
    if score <= 0:
        return RISK_UNKNOWN

    if cvss_version == 2:
        if score >= 7.0:
            return RISK_HIGH
        if score >= 4.0:
            return RISK_MEDIUM
        return RISK_LOW

    if score >= 9.0:
        return RISK_CRITICAL
    if score >= 7.0:
        return RISK_HIGH
    if score >= 4.0:
        return RISK_MEDIUM
    return RISK_LOW


def _cvss3_base_score(vector: str) -> float | None:
    metrics = _cvss_metrics(vector)
    if metrics is None:
        return None

    required = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
    if any(metric not in metrics for metric in required):
        return None

    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}.get(metrics["AV"])
    ac = {"L": 0.77, "H": 0.44}.get(metrics["AC"])
    ui = {"N": 0.85, "R": 0.62}.get(metrics["UI"])
    scope_changed = metrics["S"] == "C"

    if scope_changed:
        pr = {"N": 0.85, "L": 0.68, "H": 0.50}.get(metrics["PR"])
    else:
        pr = {"N": 0.85, "L": 0.62, "H": 0.27}.get(metrics["PR"])

    confidentiality = {"H": 0.56, "L": 0.22, "N": 0.0}.get(metrics["C"])
    integrity = {"H": 0.56, "L": 0.22, "N": 0.0}.get(metrics["I"])
    availability = {"H": 0.56, "L": 0.22, "N": 0.0}.get(metrics["A"])

    if None in (
        av,
        ac,
        pr,
        ui,
        confidentiality,
        integrity,
        availability,
    ):
        return None

    iss = 1 - (
        (1 - confidentiality) * (1 - integrity) * (1 - availability)
    )

    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0

    if scope_changed:
        return _round_up_tenth(min(1.08 * (impact + exploitability), 10.0))
    return _round_up_tenth(min(impact + exploitability, 10.0))


def _cvss2_base_score(vector: str) -> float | None:
    metrics = _cvss_metrics(vector)
    if metrics is None:
        return None

    required = ("AV", "AC", "AU", "C", "I", "A")
    if any(metric not in metrics for metric in required):
        return None

    av = {"L": 0.395, "A": 0.646, "N": 1.0}.get(metrics["AV"])
    ac = {"H": 0.35, "M": 0.61, "L": 0.71}.get(metrics["AC"])
    authentication = {"M": 0.45, "S": 0.56, "N": 0.704}.get(metrics["AU"])
    confidentiality = {"N": 0.0, "P": 0.275, "C": 0.660}.get(metrics["C"])
    integrity = {"N": 0.0, "P": 0.275, "C": 0.660}.get(metrics["I"])
    availability = {"N": 0.0, "P": 0.275, "C": 0.660}.get(metrics["A"])

    if None in (
        av,
        ac,
        authentication,
        confidentiality,
        integrity,
        availability,
    ):
        return None

    impact = 10.41 * (
        1 - (1 - confidentiality) * (1 - integrity) * (1 - availability)
    )
    exploitability = 20 * av * ac * authentication
    f_impact = 0.0 if impact == 0 else 1.176
    score = ((0.6 * impact) + (0.4 * exploitability) - 1.5) * f_impact
    return _round_nearest_tenth(max(0.0, min(score, 10.0)))


def _cvss_metrics(vector: str) -> dict[str, str] | None:
    if not isinstance(vector, str) or not vector.strip():
        return None

    parts = vector.strip().split("/")
    if parts and parts[0].upper().startswith("CVSS:"):
        parts = parts[1:]

    metrics: dict[str, str] = {}
    for part in parts:
        if ":" not in part:
            continue
        key, value = part.split(":", 1)
        key = key.strip().upper()
        value = value.strip().upper()
        if key and value:
            metrics[key] = value

    return metrics or None


def _round_up_tenth(value: float) -> float:
    return math.ceil((value * 10) - 1e-9) / 10


def _round_nearest_tenth(value: float) -> float:
    return math.floor((value * 10) + 0.5) / 10


def _resolved_version(entry: dict[str, Any]) -> str | None:
    value = entry.get("version")
    if not isinstance(value, str):
        return None

    candidate = value.strip()
    if not candidate:
        return None

    try:
        Version(candidate)
    except InvalidVersion:
        return None

    return candidate


def _normalized_package_name(entry: dict[str, Any]) -> str | None:
    value = entry.get("normalized_name", entry.get("name"))
    if not isinstance(value, str) or not value.strip():
        return None
    normalized = normalize_package_name(value.strip())
    return normalized or None


def _display_name(entry: dict[str, Any], package_name: str) -> str:
    value = entry.get("name")
    if isinstance(value, str) and value.strip():
        return value.strip()
    return package_name


def _declared_constraints(entry: dict[str, Any]) -> list[str]:
    values: set[str] = set()

    def add(value: Any) -> None:
        if isinstance(value, str):
            if value.strip():
                values.add(value.strip())
            return

        if isinstance(value, (list, tuple)):
            for item in value:
                add(item)

    for key in (
        "version_constraints",
        "version_constraint",
        "declared_constraints",
    ):
        add(entry.get(key))

    declarations = entry.get("declarations")
    if isinstance(declarations, list):
        for declaration in declarations:
            if isinstance(declaration, dict):
                add(declaration.get("version_constraints"))
                add(declaration.get("version_constraint"))
                add(declaration.get("constraints"))

    return sorted(values)


def _finding_id(finding: dict[str, Any]) -> str | None:
    value = finding.get("vulnerability_id", finding.get("id"))
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _vulnerability_ids(findings: list[dict[str, Any]]) -> list[str]:
    identifiers: list[str] = []
    for finding in findings:
        identifier = _finding_id(finding)
        if identifier is not None and identifier not in identifiers:
            identifiers.append(identifier)
    return identifiers


def _fixed_versions(findings: list[dict[str, Any]]) -> list[str]:
    values: set[str] = set()
    for finding in findings:
        fixed = finding.get("fixed_versions")
        if isinstance(fixed, (list, tuple)):
            for item in fixed:
                if isinstance(item, str) and item.strip():
                    values.add(item.strip())
        single = finding.get("fixed_version")
        if isinstance(single, str) and single.strip():
            values.add(single.strip())
    return sorted(values)


def _highest_risk(risks: list[str]) -> str | None:
    known = [
        risk
        for risk in risks
        if risk in _RISK_RANK and risk != RISK_UNKNOWN
    ]
    if known:
        return max(known, key=lambda risk: _RISK_RANK[risk])
    if any(risk == RISK_UNKNOWN for risk in risks):
        return RISK_UNKNOWN
    return None


def _empty_risk_counts() -> dict[str, int]:
    return {level: 0 for level in RISK_LEVELS}


def _error_result(
    message: str,
    *,
    project_directory: str = "",
    project_name: str = "",
    warnings: list[str] | None = None,
    errors: list[str] | None = None,
) -> RiskAnalysisResult:
    message = message or "risk analysis failed"
    combined_warnings = _dedupe([message] + list(warnings or []))
    combined_errors = _dedupe([message] + list(errors or []))
    risk_counts = _empty_risk_counts()

    summary = {
        "total_dependencies": 0,
        "risk_counts": risk_counts,
        "vulnerable_dependency_count": 0,
        "unresolved_dependency_count": 0,
        "incomplete_coverage_dependency_count": 0,
        "project_risk": RISK_UNKNOWN,
        "risk_reason": message,
        "scan_status": VULNERABILITY_STATUS_ERROR,
        "scan_coverage": COVERAGE_UNAVAILABLE,
    }

    return {
        "status": STATUS_ERROR,
        "source_status": DISCOVERY_STATUS_ERROR,
        "project_directory": project_directory,
        "project_name": project_name,
        "summary": summary,
        "project_risk": RISK_UNKNOWN,
        "overall_risk": RISK_UNKNOWN,
        "risk_counts": risk_counts,
        "total_dependencies": 0,
        "vulnerable_dependency_count": 0,
        "unresolved_dependency_count": 0,
        "incomplete_coverage_dependency_count": 0,
        "scan_status": VULNERABILITY_STATUS_ERROR,
        "scan_coverage": COVERAGE_UNAVAILABLE,
        "risk_reason": message,
        "dependencies": [],
        "warnings": combined_warnings,
        "errors": combined_errors,
        "error": message,
    }


def _string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, list):
        return [
            item.strip()
            for item in value
            if isinstance(item, str) and item.strip()
        ]
    return []


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
