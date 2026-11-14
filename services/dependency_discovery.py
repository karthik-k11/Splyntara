"""Dependency discovery engine.

The engine inspects a user-supplied project directory for supported manifest
files, parses their contents through :mod:`services.manifest_parsers`, and
combines the declarations into a normalized dependency inventory.

It is a static manifest inspection tool. It never executes project code, never
installs or resolves packages, and never sends project data anywhere.
"""

import os
from pathlib import Path
from typing import Any

from services.manifest_parsers import (
    FORMAT_PYPROJECT,
    FORMAT_REQUIREMENTS,
    MANIFEST_ORDER,
    MANIFEST_PARSERS,
    OPTIONAL,
    REGULAR,
)

STATUS_SUCCESS = "success"
STATUS_PARTIAL = "partial"
STATUS_NO_MANIFESTS = "no_manifests"
STATUS_ERROR = "error"

MAX_MANIFEST_BYTES = 5 * 1024 * 1024

ScanResult = dict[str, Any]
ManifestInfo = dict[str, Any]

__all__ = [
    "FORMAT_REQUIREMENTS",
    "FORMAT_PYPROJECT",
    "STATUS_SUCCESS",
    "STATUS_PARTIAL",
    "STATUS_NO_MANIFESTS",
    "STATUS_ERROR",
    "MAX_MANIFEST_BYTES",
    "ScanResult",
    "ManifestInfo",
    "detect_manifests",
    "discover_dependencies",
    "discover_project",
    "scan_project",
]


def detect_manifests(project_directory: str | Path) -> list[ManifestInfo]:
    """Detect supported manifest files inside ``project_directory``.

    Only files directly inside the supplied directory are considered. Returns a
    list of ``{"filename", "format", "path"}`` dictionaries in a deterministic
    order. Raises :class:`ValueError` when the supplied path is not a readable
    directory.
    """
    directory = _resolve_project_directory(project_directory)
    manifests: list[ManifestInfo] = []

    for filename in MANIFEST_ORDER:
        candidate, _, _ = _inspect_manifest_candidate(directory, filename)

        if candidate is not None:
            manifest_format, _ = MANIFEST_PARSERS[filename]
            manifests.append(
                {
                    "filename": filename,
                    "format": manifest_format,
                    "path": candidate,
                }
            )

    return manifests


def discover_dependencies(project_directory: str | Path) -> ScanResult:
    """Discover and parse dependencies in ``project_directory``.

    The result always contains the same keys so callers can rely on a stable
    shape, even when the scan fails or no manifests are found. ``dependencies``
    contains every declaration, while ``inventory`` contains one normalized
    entry per package that preserves all original manifest references.
    """
    try:
        directory = _resolve_project_directory(project_directory)
    except ValueError as error:
        return _empty_result(project_directory, status=STATUS_ERROR, warnings=[str(error)])

    dependencies: list[dict[str, Any]] = []
    warnings: list[str] = []
    manifests: list[ManifestInfo] = []

    for filename in MANIFEST_ORDER:
        candidate, safe_path, safety_warning = _inspect_manifest_candidate(
            directory, filename
        )
        manifest_format, parser = MANIFEST_PARSERS[filename]

        if safety_warning is not None:
            warnings.append(safety_warning)
            manifests.append(
                {
                    "filename": filename,
                    "format": manifest_format,
                    "path": str(directory / filename),
                    "dependency_count": 0,
                    "status": "skipped",
                }
            )
            continue

        if candidate is None:
            continue

        manifest_info: ManifestInfo = {
            "filename": filename,
            "format": manifest_format,
            "path": str(candidate),
        }

        try:
            with safe_path.open("rb") as handle:
                content_bytes = handle.read(MAX_MANIFEST_BYTES + 1)
        except OSError as error:
            reason = getattr(error, "strerror", None)
            warning = f"{filename}: could not be read"
            if reason:
                warning += f" ({reason})"
            warnings.append(warning)
            manifests.append(
                {
                    **manifest_info,
                    "dependency_count": 0,
                    "status": "unreadable",
                }
            )
            continue

        if len(content_bytes) > MAX_MANIFEST_BYTES:
            warnings.append(
                f"{filename}: file exceeds the {MAX_MANIFEST_BYTES}-byte size "
                "limit; it was skipped"
            )
            manifests.append(
                {
                    **manifest_info,
                    "dependency_count": 0,
                    "status": "skipped",
                }
            )
            continue

        try:
            content = content_bytes.decode("utf-8")
        except UnicodeDecodeError:
            warnings.append(f"{filename}: could not be read (invalid UTF-8)")
            manifests.append(
                {
                    **manifest_info,
                    "dependency_count": 0,
                    "status": "unreadable",
                }
            )
            continue

        try:
            parse_result = parser(content, source_manifest=filename)
        except Exception:  # noqa: BLE001 - never let one file abort the scan
            warnings.append(
                f"{filename}: unexpected error while parsing; it was skipped"
            )
            manifests.append(
                {
                    **manifest_info,
                    "dependency_count": 0,
                    "status": "failed",
                }
            )
            continue

        parsed_dependencies = parse_result.get("dependencies", [])
        dependencies.extend(parsed_dependencies)
        warnings.extend(parse_result.get("warnings", []))
        manifests.append(
            {
                **manifest_info,
                "dependency_count": len(parsed_dependencies),
                "status": "parsed",
            }
        )

    duplicates = _find_duplicates(dependencies)
    inventory = _build_inventory(dependencies)
    regular_count = sum(1 for item in dependencies if item["dependency_type"] == REGULAR)
    optional_count = sum(1 for item in dependencies if item["dependency_type"] == OPTIONAL)

    if not manifests:
        status = STATUS_NO_MANIFESTS
    elif warnings or any(manifest["status"] != "parsed" for manifest in manifests):
        status = STATUS_PARTIAL
    else:
        status = STATUS_SUCCESS

    return {
        "project_directory": str(directory),
        "project_name": directory.name,
        "status": status,
        "manifests": manifests,
        "dependencies": dependencies,
        "inventory": inventory,
        "dependency_count": len(dependencies),
        "unique_dependency_count": len(inventory),
        "regular_dependency_count": regular_count,
        "optional_dependency_count": optional_count,
        "duplicates": duplicates,
        "warnings": warnings,
    }


def discover_project(project_directory: str | Path) -> ScanResult:
    """Alias for :func:`discover_dependencies` used by API callers."""
    return discover_dependencies(project_directory)


def scan_project(project_directory: str | Path) -> ScanResult:
    """Backward-compatible alias for :func:`discover_dependencies`."""
    return discover_dependencies(project_directory)


def _resolve_project_directory(project_directory: str | Path) -> Path:
    """Validate and resolve a project directory path.

    Raises :class:`ValueError` with a clear message when the path is empty,
    does not exist, cannot be resolved, or is not a directory.
    """
    if project_directory is None:
        raise ValueError("no project directory was provided")

    raw = str(project_directory).strip()

    if not raw:
        raise ValueError("no project directory was provided")

    try:
        directory = Path(raw).expanduser().resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as error:
        raise ValueError("could not access project directory") from error

    if not directory.is_dir():
        raise ValueError("project path is not a directory")

    try:
        with os.scandir(directory) as entries:
            next(entries, None)
    except OSError as error:
        raise ValueError("project directory could not be read") from error

    return directory


def _inspect_manifest_candidate(
    directory: Path,
    filename: str,
) -> tuple[Path | None, Path | None, str | None]:
    """Return a safe manifest path or a warning when it escapes the project.

    Symbolic links are allowed only when their resolved target still lives
    inside the resolved project directory. The resolved target is returned so
    callers read exactly the file that passed the containment check, avoiding a
    link-swap race between validation and reading.
    """
    candidate = directory / filename

    if not candidate.exists() and not candidate.is_symlink():
        return None, None, None

    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as error:
        reason = getattr(error, "strerror", None)
        warning = f"{filename}: could not be resolved safely"
        if reason:
            warning += f" ({reason})"
        return None, None, f"{warning}; it was skipped"

    if not _is_within_directory(resolved, directory):
        return None, None, (
            f"{filename}: path resolves outside the project directory; "
            "it was skipped"
        )

    if not resolved.is_file():
        return None, None, (
            f"{filename}: path is not a regular file; it was skipped"
        )

    return candidate, resolved, None


def _is_within_directory(path: Path, directory: Path) -> bool:
    """Return whether ``path`` is the same as or below ``directory``."""
    try:
        normalized_path = Path(os.path.normcase(str(path)))
        normalized_directory = Path(os.path.normcase(str(directory)))
        return normalized_path.is_relative_to(normalized_directory)
    except (OSError, ValueError):
        return False


def _empty_result(
    project_directory: str | Path,
    *,
    status: str,
    warnings: list[str],
) -> ScanResult:
    """Build a zeroed scan result for error and empty cases."""
    raw = "" if project_directory is None else str(project_directory)
    name = Path(raw).name if raw.strip() else ""

    return {
        "project_directory": raw,
        "project_name": name,
        "status": status,
        "manifests": [],
        "dependencies": [],
        "inventory": [],
        "dependency_count": 0,
        "unique_dependency_count": 0,
        "regular_dependency_count": 0,
        "optional_dependency_count": 0,
        "duplicates": [],
        "warnings": warnings,
    }


def _build_inventory(dependencies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group declarations by normalized package name.

    The inventory contains one entry per package, which removes duplicate
    declarations from the normalized view. Every original declaration remains
    available under ``declarations`` so manifest references are never lost.
    """
    groups: dict[str, list[dict[str, Any]]] = {}

    for dependency in dependencies:
        groups.setdefault(dependency["normalized_name"], []).append(dependency)

    inventory: list[dict[str, Any]] = []

    for normalized_name in sorted(groups):
        records = groups[normalized_name]
        inventory.append(
            {
                "name": records[0]["name"],
                "normalized_name": normalized_name,
                "version_constraints": sorted(
                    {
                        record["version_constraint"]
                        for record in records
                        if record["version_constraint"] is not None
                    }
                ),
                "dependency_types": sorted(
                    {record["dependency_type"] for record in records}
                ),
                "source_manifests": sorted(
                    {record["source_manifest"] for record in records}
                ),
                "optional_groups": sorted(
                    {
                        record["optional_group"]
                        for record in records
                        if record["optional_group"] is not None
                    }
                ),
                "declarations": list(records),
            }
        )

    return inventory


def _find_duplicates(dependencies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group repeated declarations by normalized name.

    Declarations are never removed from ``dependencies``. Each group is
    classified as ``"duplicate"`` when every declaration is identical, or
    ``"conflict"`` when the version constraints, extras, markers, dependency
    types or optional groups differ.
    """
    groups: dict[str, list[dict[str, Any]]] = {}

    for dependency in dependencies:
        groups.setdefault(dependency["normalized_name"], []).append(dependency)

    duplicates: list[dict[str, Any]] = []

    for normalized_name, records in groups.items():
        if len(records) < 2:
            continue

        signatures = {
            (
                record["version_constraint"],
                tuple(record["extras"]),
                record["environment_marker"],
                record["dependency_type"],
                record["optional_group"],
            )
            for record in records
        }
        kind = "duplicate" if len(signatures) == 1 else "conflict"

        duplicates.append(
            {
                "normalized_name": normalized_name,
                "kind": kind,
                "count": len(records),
                "declarations": [
                    {
                        "name": record["name"],
                        "version_constraint": record["version_constraint"],
                        "dependency_type": record["dependency_type"],
                        "optional_group": record["optional_group"],
                        "source_manifest": record["source_manifest"],
                        "raw_declaration": record["raw_declaration"],
                    }
                    for record in records
                ],
            }
        )

    duplicates.sort(key=lambda group: group["normalized_name"])
    return duplicates
