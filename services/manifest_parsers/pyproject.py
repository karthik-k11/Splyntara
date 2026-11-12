"""Parser for PEP 621 ``pyproject.toml`` dependency declarations."""

import tomllib
from typing import Any

from services.manifest_parsers.common import (
    OPTIONAL,
    REGULAR,
    Dependency,
    ParseResult,
    parse_requirement_string,
)

PYPROJECT_FILENAME = "pyproject.toml"

__all__ = [
    "PYPROJECT_FILENAME",
    "parse_pyproject_toml",
]


def parse_pyproject_toml(
    content: str,
    source_manifest: str = PYPROJECT_FILENAME,
) -> ParseResult:
    """Parse the contents of a ``pyproject.toml`` file.

    Only the PEP 621 ``[project].dependencies`` and
    ``[project.optional-dependencies]`` tables are read. Optional dependency
    groups are preserved on each record via ``optional_group`` and marked with
    ``dependency_type == "optional"``. Malformed TOML yields a warning instead
    of raising.
    """
    dependencies: list[Dependency] = []
    warnings: list[str] = []

    try:
        document = tomllib.loads(content)
    except tomllib.TOMLDecodeError as error:
        return {
            "dependencies": dependencies,
            "warnings": [f"{source_manifest}: malformed TOML: {error}"],
        }

    project = document.get("project")

    if project is None:
        warnings.append(
            f"{source_manifest}: no [project] table found; no dependencies were read"
        )
        return {"dependencies": dependencies, "warnings": warnings}

    if not isinstance(project, dict):
        warnings.append(
            f"{source_manifest}: [project] is not a table; no dependencies were read"
        )
        return {"dependencies": dependencies, "warnings": warnings}

    _collect_entries(
        project.get("dependencies"),
        source_manifest=source_manifest,
        dependency_type=REGULAR,
        optional_group=None,
        field_name="[project].dependencies",
        dependencies=dependencies,
        warnings=warnings,
    )

    optional_groups = project.get("optional-dependencies")

    if optional_groups is None:
        return {"dependencies": dependencies, "warnings": warnings}

    if not isinstance(optional_groups, dict):
        warnings.append(
            f"{source_manifest}: [project.optional-dependencies] is not a table; "
            "optional dependencies were skipped"
        )
        return {"dependencies": dependencies, "warnings": warnings}

    for group_name, entries in optional_groups.items():
        _collect_entries(
            entries,
            source_manifest=source_manifest,
            dependency_type=OPTIONAL,
            optional_group=str(group_name),
            field_name=f"[project.optional-dependencies.{group_name}]",
            dependencies=dependencies,
            warnings=warnings,
        )

    return {"dependencies": dependencies, "warnings": warnings}


def _collect_entries(
    entries: Any,
    *,
    source_manifest: str,
    dependency_type: str,
    optional_group: str | None,
    field_name: str,
    dependencies: list[Dependency],
    warnings: list[str],
) -> None:
    """Parse a list of PEP 508 strings from a ``pyproject.toml`` field."""
    if entries is None:
        return

    if not isinstance(entries, list):
        warnings.append(
            f"{source_manifest}: {field_name} is not an array of strings; "
            "entries were skipped"
        )
        return

    for entry in entries:
        if not isinstance(entry, str):
            warnings.append(
                f"{source_manifest}: {field_name} contains a non-string entry "
                f"({entry!r}); it was skipped"
            )
            continue

        dependency, warning = parse_requirement_string(
            entry,
            source_manifest=source_manifest,
            dependency_type=dependency_type,
            optional_group=optional_group,
        )

        if warning is not None:
            warnings.append(warning)

        if dependency is not None:
            dependencies.append(dependency)
