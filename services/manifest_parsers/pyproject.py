"""Parser for PEP 621 ``pyproject.toml`` dependency declarations."""

import tomllib
from typing import Any

from services.manifest_parsers.common import (
    OPTIONAL,
    REGULAR,
    Dependency,
    ParseResult,
    normalize_package_name,
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
        poetry_result = _collect_poetry_dependencies(
            document,
            source_manifest=source_manifest,
        )
        if poetry_result is not None:
            return poetry_result
        warnings.append(
            f"{source_manifest}: no [project] or [tool.poetry] dependency table "
            "found; no dependencies were read"
        )
        return {"dependencies": dependencies, "warnings": warnings}

    if not isinstance(project, dict):
        warnings.append(
            f"{source_manifest}: [project] is not a table; no dependencies were read"
        )
        return {"dependencies": dependencies, "warnings": warnings}

    if (
        project.get("dependencies") is None
        and project.get("optional-dependencies") is None
    ):
        poetry_result = _collect_poetry_dependencies(
            document,
            source_manifest=source_manifest,
        )
        if poetry_result is not None:
            return poetry_result

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


def _collect_poetry_dependencies(
    document: dict[str, Any],
    *,
    source_manifest: str,
) -> ParseResult | None:
    tool = document.get("tool")
    poetry = tool.get("poetry") if isinstance(tool, dict) else None
    if not isinstance(poetry, dict):
        return None

    dependencies: list[Dependency] = []
    warnings: list[str] = []
    _collect_poetry_table(
        poetry.get("dependencies"),
        source_manifest=source_manifest,
        dependency_type=REGULAR,
        optional_group=None,
        field_name="[tool.poetry.dependencies]",
        dependencies=dependencies,
        warnings=warnings,
    )

    dev_dependencies = poetry.get("dev-dependencies")
    _collect_poetry_table(
        dev_dependencies,
        source_manifest=source_manifest,
        dependency_type=OPTIONAL,
        optional_group="dev",
        field_name="[tool.poetry.dev-dependencies]",
        dependencies=dependencies,
        warnings=warnings,
    )

    groups = poetry.get("group")
    if groups is not None and not isinstance(groups, dict):
        warnings.append(
            f"{source_manifest}: [tool.poetry.group] is not a table; "
            "dependency groups were skipped"
        )
    elif isinstance(groups, dict):
        for group_name, group in groups.items():
            if not isinstance(group, dict):
                warnings.append(
                    f"{source_manifest}: [tool.poetry.group.{group_name}] "
                    "is not a table; it was skipped"
                )
                continue
            optional = group.get("optional") is True
            _collect_poetry_table(
                group.get("dependencies"),
                source_manifest=source_manifest,
                dependency_type=OPTIONAL if optional else REGULAR,
                optional_group=str(group_name),
                field_name=f"[tool.poetry.group.{group_name}.dependencies]",
                dependencies=dependencies,
                warnings=warnings,
            )

    return {"dependencies": dependencies, "warnings": warnings}


def _collect_poetry_table(
    entries: Any,
    *,
    source_manifest: str,
    dependency_type: str,
    optional_group: str | None,
    field_name: str,
    dependencies: list[Dependency],
    warnings: list[str],
) -> None:
    if entries is None:
        return
    if not isinstance(entries, dict):
        warnings.append(
            f"{source_manifest}: {field_name} is not a table; entries were skipped"
        )
        return

    for raw_name, value in entries.items():
        if not isinstance(raw_name, str) or not raw_name.strip():
            warnings.append(
                f"{source_manifest}: {field_name} contains an invalid package name; "
                "it was skipped"
            )
            continue
        if raw_name.strip().lower() == "python":
            continue

        if isinstance(value, str):
            package_data: dict[str, Any] = {"version": value}
        elif isinstance(value, dict):
            package_data = value
        else:
            warnings.append(
                f"{source_manifest}: {field_name}.{raw_name} has an unsupported "
                "dependency value; it was skipped"
            )
            continue

        version = package_data.get("version")
        version_constraint = (
            version.strip()
            if isinstance(version, str) and version.strip() not in {"", "*"}
            else None
        )
        extras = package_data.get("extras")
        if not isinstance(extras, list):
            extras = []
        optional = package_data.get("optional") is True
        package_group = optional_group or ("optional" if optional else None)

        dependencies.append(
            {
                "name": raw_name.strip(),
                "normalized_name": normalize_package_name(raw_name.strip()),
                "version_constraint": version_constraint,
                "extras": sorted(
                    item.strip() for item in extras
                    if isinstance(item, str) and item.strip()
                ),
                "environment_marker": (
                    package_data.get("markers")
                    if isinstance(package_data.get("markers"), str)
                    else None
                ),
                "dependency_type": (
                    OPTIONAL if optional else dependency_type
                ),
                "optional_group": package_group,
                "source_manifest": source_manifest,
                "raw_declaration": f"{raw_name.strip()} "
                f"{version_constraint or '*'}".strip(),
            }
        )


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
