"""Dependency discovery engine.

The engine inspects a user-supplied project directory for supported manifests
and lockfiles, parses them statically, and combines declarations with exact
package records from the selected lockfile.

It is a static manifest and lockfile inspection tool. It never executes project
code, installs packages, or sends project data anywhere.
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
from services.lockfile_parsers import LOCKFILE_ORDER, LOCKFILE_PARSERS

STATUS_SUCCESS = "success"
STATUS_PARTIAL = "partial"
STATUS_NO_MANIFESTS = "no_manifests"
STATUS_ERROR = "error"

MAX_MANIFEST_BYTES = 5 * 1024 * 1024
MAX_LOCKFILE_BYTES = 20 * 1024 * 1024

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
    "MAX_LOCKFILE_BYTES",
    "ScanResult",
    "ManifestInfo",
    "detect_manifests",
    "detect_lockfiles",
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


def detect_lockfiles(project_directory: str | Path) -> list[ManifestInfo]:
    """Detect supported lockfiles directly inside ``project_directory``."""
    directory = _resolve_project_directory(project_directory)
    lockfiles: list[ManifestInfo] = []

    for filename in LOCKFILE_ORDER:
        candidate, _, _ = _inspect_manifest_candidate(directory, filename)
        if candidate is not None:
            lockfile_format, _ = LOCKFILE_PARSERS[filename]
            lockfiles.append(
                {
                    "filename": filename,
                    "format": lockfile_format,
                    "path": candidate,
                }
            )

    return lockfiles


def discover_dependencies(project_directory: str | Path) -> ScanResult:
    """Discover and parse dependencies in ``project_directory``.

    The result always contains the same keys so callers can rely on a stable
    shape, even when the scan fails or no manifests are found. ``dependencies``
    contains every declaration, while ``inventory`` contains one entry per
    package/version and preserves all original manifest references.
    """
    try:
        directory = _resolve_project_directory(project_directory)
    except ValueError as error:
        return _empty_result(project_directory, status=STATUS_ERROR, warnings=[str(error)])

    dependencies: list[dict[str, Any]] = []
    warnings: list[str] = []
    manifests: list[ManifestInfo] = []
    lockfiles: list[ManifestInfo] = []

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
    lockfile_resolution = _resolve_lockfiles(
        directory,
        inventory,
        warnings,
        lockfiles,
        has_manifests=bool(manifests),
    )
    inventory = lockfile_resolution["inventory"]
    regular_count = sum(1 for item in dependencies if item["dependency_type"] == REGULAR)
    optional_count = sum(1 for item in dependencies if item["dependency_type"] == OPTIONAL)

    if not manifests and not lockfiles:
        status = STATUS_NO_MANIFESTS
    elif warnings or any(manifest["status"] != "parsed" for manifest in manifests):
        status = STATUS_PARTIAL
    elif any(lockfile["status"] != "parsed" for lockfile in lockfiles):
        status = STATUS_PARTIAL
    else:
        status = STATUS_SUCCESS

    return {
        "project_directory": str(directory),
        "project_name": directory.name,
        "status": status,
        "manifests": manifests,
        "lockfiles": lockfiles,
        "resolution": lockfile_resolution["resolution"],
        "dependencies": dependencies,
        "inventory": inventory,
        "dependency_count": len(dependencies),
        "unique_dependency_count": len(inventory),
        "resolved_dependency_count": sum(
            1 for item in inventory if item.get("version_resolved")
        ),
        "unresolved_dependency_count": sum(
            1 for item in inventory if not item.get("version_resolved")
        ),
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

    if len(raw) >= 2 and raw[0] == raw[-1] == '"':
        raw = raw[1:-1]

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
        "lockfiles": [],
        "resolution": {
            "status": "unavailable",
            "lockfile": None,
            "resolved_dependency_count": 0,
            "unresolved_dependency_count": 0,
            "warnings": list(warnings),
        },
        "dependencies": [],
        "inventory": [],
        "dependency_count": 0,
        "unique_dependency_count": 0,
        "resolved_dependency_count": 0,
        "unresolved_dependency_count": 0,
        "regular_dependency_count": 0,
        "optional_dependency_count": 0,
        "duplicates": [],
        "warnings": warnings,
    }


def _build_inventory(dependencies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group declarations by normalized package name before lockfile overlay.

    Every original declaration remains under ``declarations`` so manifest
    references are never lost.
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
                "version": None,
                "resolved_version": None,
                "version_resolved": False,
                "resolution_source": None,
                "dependency_classification": "direct",
                "package_source": None,
                "package_sources": [],
                "dependency_relationships": [],
                "lockfile_metadata": {},
                "declarations": list(records),
            }
        )

    return inventory


def _resolve_lockfiles(
    directory: Path,
    inventory: list[dict[str, Any]],
    warnings: list[str],
    lockfiles: list[ManifestInfo],
    *,
    has_manifests: bool,
) -> dict[str, Any]:
    """Parse one selected lockfile and overlay exact versions on the inventory."""
    present: list[tuple[str, Path | None, Path | None, str | None]] = []
    for filename in LOCKFILE_ORDER:
        candidate, safe_path, safety_warning = _inspect_manifest_candidate(
            directory, filename
        )
        if candidate is not None or safety_warning is not None:
            present.append((filename, candidate, safe_path, safety_warning))

    if len(present) > 1:
        message = (
            "Both uv.lock and poetry.lock are present; their environments may "
            "differ, so neither lockfile was used."
        )
        warnings.append(message)
        for filename, candidate, _, _ in present:
            lockfile_format, _ = LOCKFILE_PARSERS[filename]
            lockfiles.append(
                {
                    "filename": filename,
                    "format": lockfile_format,
                    "path": str(candidate or (directory / filename)),
                    "package_count": 0,
                    "status": "ambiguous",
                }
            )
        return _unresolved_resolution(inventory, "ambiguous", warnings, lockfile=None)

    if not present:
        message = (
            "No supported Python lockfile (uv.lock or poetry.lock) was found; "
            "dependencies without explicit resolved versions remain unresolved."
        )
        warnings.append(message)
        return _unresolved_resolution(inventory, "missing", warnings, lockfile=None)

    filename, candidate, safe_path, safety_warning = present[0]
    lockfile_format, parser = LOCKFILE_PARSERS[filename]
    info: ManifestInfo = {
        "filename": filename,
        "format": lockfile_format,
        "path": str(candidate or (directory / filename)),
    }
    lockfiles.append(info)

    if safety_warning is not None or candidate is None or safe_path is None:
        message = safety_warning or f"{filename}: could not be read safely; it was skipped"
        warnings.append(message)
        info.update({"package_count": 0, "status": "skipped"})
        return _unresolved_resolution(inventory, "unsafe", warnings, lockfile=filename)

    try:
        with safe_path.open("rb") as handle:
            content_bytes = handle.read(MAX_LOCKFILE_BYTES + 1)
    except OSError as error:
        reason = getattr(error, "strerror", None)
        message = f"{filename}: could not be read"
        if reason:
            message += f" ({reason})"
        warnings.append(message)
        info.update({"package_count": 0, "status": "unreadable"})
        return _unresolved_resolution(inventory, "unreadable", warnings, lockfile=filename)

    if len(content_bytes) > MAX_LOCKFILE_BYTES:
        warnings.append(
            f"{filename}: file exceeds the {MAX_LOCKFILE_BYTES}-byte size limit; "
            "it was skipped"
        )
        info.update({"package_count": 0, "status": "skipped"})
        return _unresolved_resolution(inventory, "oversized", warnings, lockfile=filename)

    try:
        content = content_bytes.decode("utf-8")
    except UnicodeDecodeError:
        warnings.append(f"{filename}: could not be read (invalid UTF-8)")
        info.update({"package_count": 0, "status": "unreadable"})
        return _unresolved_resolution(inventory, "unreadable", warnings, lockfile=filename)

    try:
        parse_result = parser(content, source_lockfile=filename)
    except Exception:  # noqa: BLE001 - malformed lock data must not abort discovery
        message = f"{filename}: unexpected error while parsing; it was skipped"
        warnings.append(message)
        info.update({"package_count": 0, "status": "failed"})
        return _unresolved_resolution(inventory, "failed", warnings, lockfile=filename)
    parse_status = parse_result.get("status", "unsupported")
    packages = parse_result.get("packages", [])
    if not isinstance(packages, list):
        packages = []
        parse_status = "unsupported"
    parse_warnings = parse_result.get("warnings", [])
    if isinstance(parse_warnings, list):
        warnings.extend(item for item in parse_warnings if isinstance(item, str))
    else:
        warnings.append(f"{filename}: parser returned invalid warnings")
    info.update(
        {
            "package_count": len(packages),
            "status": parse_status,
        }
    )

    if parse_status not in {"parsed", "partial"}:
        resolution_status = parse_status
        return _unresolved_resolution(
            inventory,
            resolution_status,
            warnings,
            lockfile=filename,
        )

    resolved_inventory, missing_direct = _apply_locked_packages(
        inventory,
        packages,
        lockfile=filename,
    )
    if missing_direct:
        warnings.append(
            f"{missing_direct} declared dependency(ies) were not present in "
            f"{filename} and remain unresolved."
        )
    if not has_manifests and packages:
        warnings.append(
            f"{filename}: no supported dependency manifest was found; direct and "
            "transitive classifications are unknown."
        )
    resolution_status = (
        "resolved"
        if parse_status == "parsed" and not missing_direct and has_manifests
        else "partial"
    )
    return {
        "inventory": resolved_inventory,
        "resolution": {
            "status": resolution_status,
            "lockfile": filename,
            "resolved_dependency_count": sum(
                1 for item in resolved_inventory if item.get("version_resolved")
            ),
            "unresolved_dependency_count": sum(
                1 for item in resolved_inventory if not item.get("version_resolved")
            ),
            "warnings": list(warnings),
        },
    }


def _apply_locked_packages(
    inventory: list[dict[str, Any]],
    packages: list[Any],
    *,
    lockfile: str,
) -> tuple[list[dict[str, Any]], int]:
    declared_by_name = {
        item["normalized_name"]: item
        for item in inventory
        if isinstance(item.get("normalized_name"), str)
    }
    locked_by_name: dict[str, dict[str, dict[str, Any]]] = {}
    for package in packages:
        if not isinstance(package, dict):
            continue
        if package.get("is_project_root") is True:
            continue
        normalized_name = package.get("normalized_name")
        version = package.get("version")
        if not isinstance(normalized_name, str) or not normalized_name:
            continue
        if not isinstance(version, str) or not version:
            continue
        versions = locked_by_name.setdefault(normalized_name, {})
        existing = versions.get(version)
        if existing is None:
            versions[version] = {
                **package,
                "package_sources": (
                    [package["package_source"]]
                    if isinstance(package.get("package_source"), dict)
                    else []
                ),
                "dependency_relationships": _dedupe_records(
                    package.get("dependency_relationships")
                ),
                "lockfile_metadata": (
                    dict(package["lockfile_metadata"])
                    if isinstance(package.get("lockfile_metadata"), dict)
                    else {}
                ),
            }
            continue

        source = package.get("package_source")
        if isinstance(source, dict) and source not in existing["package_sources"]:
            existing["package_sources"].append(source)
        existing["dependency_relationships"] = _dedupe_records(
            existing["dependency_relationships"]
            + _dedupe_records(package.get("dependency_relationships"))
        )
        if isinstance(package.get("lockfile_metadata"), dict):
            existing["lockfile_metadata"].update(package["lockfile_metadata"])

    resolved_inventory: list[dict[str, Any]] = []
    matched_names: set[str] = set()
    for normalized_name in sorted(locked_by_name):
        declaration = declared_by_name.get(normalized_name)
        if declaration is not None:
            matched_names.add(normalized_name)
        else:
            classification = "transitive" if inventory else "unknown"
            dependency_types = [classification]
        for version in sorted(locked_by_name[normalized_name]):
            package = locked_by_name[normalized_name][version]
            if declaration is None:
                entry: dict[str, Any] = {
                    "name": package.get("name", normalized_name),
                    "normalized_name": normalized_name,
                    "version_constraints": [],
                    "dependency_types": dependency_types,
                    "source_manifests": [],
                    "optional_groups": [],
                    "declarations": [],
                }
            else:
                entry = dict(declaration)
            sources = package["package_sources"]
            entry.update(
                {
                    "version": version,
                    "resolved_version": version,
                    "version_resolved": True,
                    "resolution_source": lockfile,
                    "dependency_classification": (
                        "direct" if declaration is not None
                        else "transitive" if inventory
                        else "unknown"
                    ),
                    "package_source": sources[0] if len(sources) == 1 else None,
                    "package_sources": list(sources),
                    "dependency_relationships": package[
                        "dependency_relationships"
                    ],
                    "lockfile_metadata": package["lockfile_metadata"],
                }
            )
            resolved_inventory.append(entry)

    missing_direct = 0
    for item in inventory:
        if item["normalized_name"] not in matched_names:
            unresolved = dict(item)
            unresolved.update(
                {
                    "version": None,
                    "resolved_version": None,
                    "version_resolved": False,
                    "resolution_source": None,
                    "dependency_classification": "direct",
                    "package_source": None,
                    "package_sources": [],
                    "dependency_relationships": [],
                    "lockfile_metadata": {},
                }
            )
            resolved_inventory.append(unresolved)
            missing_direct += 1

    resolved_inventory.sort(
        key=lambda item: (
            item["normalized_name"],
            item["version"] or "",
        )
    )
    return resolved_inventory, missing_direct


def _unresolved_resolution(
    inventory: list[dict[str, Any]],
    status: str,
    warnings: list[str],
    *,
    lockfile: str | None,
) -> dict[str, Any]:
    unresolved_inventory = []
    for item in inventory:
        unresolved = dict(item)
        unresolved.update(
            {
                "version": None,
                "resolved_version": None,
                "version_resolved": False,
                "resolution_source": None,
                "dependency_classification": (
                    "direct" if unresolved.get("declarations") else "unknown"
                ),
                "package_source": None,
                "package_sources": [],
                "dependency_relationships": [],
                "lockfile_metadata": {},
            }
        )
        unresolved_inventory.append(unresolved)
    return {
        "inventory": unresolved_inventory,
        "resolution": {
            "status": status,
            "lockfile": lockfile,
            "resolved_dependency_count": 0,
            "unresolved_dependency_count": len(unresolved_inventory),
            "warnings": list(warnings),
        },
    }


def _dedupe_records(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, dict):
            continue
        signature = repr(sorted(item.items()))
        if signature not in seen:
            seen.add(signature)
            result.append(dict(item))
    return result


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
