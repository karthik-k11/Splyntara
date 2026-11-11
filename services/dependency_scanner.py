"""Dependency discovery scanner.

The scanner inspects a user-supplied project directory for supported manifest
files, hands their contents to :mod:`services.dependency_parser`, and combines
the parsed declarations into a single structured inventory with scan metadata.

It is a static manifest inspection tool. It never executes project code, never
installs or resolves packages, and never sends project data anywhere.
"""

from pathlib import Path
from typing import Any

from services.dependency_parser import (
    OPTIONAL,
    PYPROJECT_FILENAME,
    REGULAR,
    REQUIREMENTS_FILENAME,
    parse_pyproject_toml,
    parse_requirements_txt,
)

FORMAT_REQUIREMENTS = "requirements"
FORMAT_PYPROJECT = "pyproject"

STATUS_SUCCESS = "success"
STATUS_PARTIAL = "partial"
STATUS_NO_MANIFESTS = "no_manifests"
STATUS_ERROR = "error"

# Manifest filename -> (format identifier, parser callable).
_MANIFEST_HANDLERS = {
    REQUIREMENTS_FILENAME: (FORMAT_REQUIREMENTS, parse_requirements_txt),
    PYPROJECT_FILENAME: (FORMAT_PYPROJECT, parse_pyproject_toml),
}

# Deterministic processing order for reproducible inventories.
_MANIFEST_ORDER = (REQUIREMENTS_FILENAME, PYPROJECT_FILENAME)

ScanResult = dict[str, Any]

__all__ = [
    "FORMAT_REQUIREMENTS",
    "FORMAT_PYPROJECT",
    "STATUS_SUCCESS",
    "STATUS_PARTIAL",
    "STATUS_NO_MANIFESTS",
    "STATUS_ERROR",
    "detect_manifests",
    "scan_project",
]


def detect_manifests(project_directory: str | Path) -> list[dict[str, Any]]:
    """Detect supported manifest files inside ``project_directory``.

    Only files directly inside the supplied directory are considered. Returns a
    list of ``{"filename", "format", "path"}`` dictionaries in a deterministic
    order. Raises :class:`ValueError` when the supplied path is not a readable
    directory.
    """
    directory = _resolve_project_directory(project_directory)
    manifests: list[dict[str, Any]] = []

    for filename in _MANIFEST_ORDER:
        candidate = directory / filename

        if candidate.is_file():
            manifest_format, _ = _MANIFEST_HANDLERS[filename]
            manifests.append(
                {
                    "filename": filename,
                    "format": manifest_format,
                    "path": candidate,
                }
            )

    return manifests


def scan_project(project_directory: str | Path) -> ScanResult:
    """Scan ``project_directory`` and return a structured dependency inventory.

    The result always contains the same keys so callers can rely on a stable
    shape, even when the scan fails or no manifests are found.
    """
    try:
        directory = _resolve_project_directory(project_directory)
    except ValueError as error:
        return _empty_result(project_directory, status=STATUS_ERROR, warnings=[str(error)])

    dependencies: list[dict[str, Any]] = []
    warnings: list[str] = []
    manifests: list[dict[str, Any]] = []

    for filename in _MANIFEST_ORDER:
        candidate = directory / filename

        if not candidate.is_file():
            continue

        manifest_format, parser = _MANIFEST_HANDLERS[filename]

        try:
            content = candidate.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as error:
            warnings.append(f"{filename}: could not be read: {error}")
            manifests.append(
                {
                    "filename": filename,
                    "format": manifest_format,
                    "dependency_count": 0,
                    "status": "unreadable",
                }
            )
            continue

        try:
            parse_result = parser(content, source_manifest=filename)
        except Exception as error:  # noqa: BLE001 - never let one file abort the scan
            warnings.append(
                f"{filename}: unexpected error while parsing "
                f"({type(error).__name__}: {error})"
            )
            manifests.append(
                {
                    "filename": filename,
                    "format": manifest_format,
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
                "filename": filename,
                "format": manifest_format,
                "dependency_count": len(parsed_dependencies),
                "status": "parsed",
            }
        )

    duplicates = _find_duplicates(dependencies)
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
        "dependency_count": len(dependencies),
        "regular_dependency_count": regular_count,
        "optional_dependency_count": optional_count,
        "duplicates": duplicates,
        "warnings": warnings,
    }


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
    except (OSError, RuntimeError) as error:
        raise ValueError(f"could not access project directory {raw!r}: {error}") from error

    if not directory.is_dir():
        raise ValueError(f"project path {raw!r} is not a directory")

    return directory


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
        "dependency_count": 0,
        "regular_dependency_count": 0,
        "optional_dependency_count": 0,
        "duplicates": [],
        "warnings": warnings,
    }


def _find_duplicates(dependencies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group repeated declarations by normalized name.

    Declarations are never removed. Each group is classified as ``"duplicate"``
    when every declaration is identical, or ``"conflict"`` when the version
    constraints, extras, markers or dependency types differ.
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
                        "source_manifest": record["source_manifest"],
                        "raw_declaration": record["raw_declaration"],
                    }
                    for record in records
                ],
            }
        )

    duplicates.sort(key=lambda group: group["normalized_name"])
    return duplicates
