"""Static parsing of Python dependency manifests.

This module turns PEP 508 dependency declarations found in ``requirements.txt``
and ``pyproject.toml`` into a consistent, structured dependency record.

The parsing here is purely static. It never executes code from the scanned
project, never installs or resolves packages, and never contacts external
services. A parsed version constraint is a *declaration*, not an installed
version, and must not be treated as one.
"""

import tomllib
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

REQUIREMENTS_FILENAME = "requirements.txt"
PYPROJECT_FILENAME = "pyproject.toml"

REGULAR = "regular"
OPTIONAL = "optional"

Dependency = dict[str, Any]
ParseResult = dict[str, Any]

__all__ = [
    "REQUIREMENTS_FILENAME",
    "PYPROJECT_FILENAME",
    "REGULAR",
    "OPTIONAL",
    "Dependency",
    "ParseResult",
    "normalize_package_name",
    "parse_requirement_string",
    "parse_requirements_txt",
    "parse_pyproject_toml",
]


def normalize_package_name(name: str) -> str:
    """Return the PEP 503 normalized form of a package name.

    Normalization lower-cases the name and collapses runs of ``-``, ``_`` and
    ``.`` into a single ``-`` so that equivalent names compare equal.
    """
    return canonicalize_name(name)


def parse_requirement_string(
    declaration: str,
    *,
    source_manifest: str,
    dependency_type: str = REGULAR,
    optional_group: str | None = None,
) -> tuple[Dependency | None, str | None]:
    """Parse a single PEP 508 declaration into a dependency record.

    Returns a ``(dependency, warning)`` tuple. Exactly one member is normally
    populated: a malformed declaration yields ``(None, warning)`` while a valid
    one yields ``(dependency, warning_or_None)``. A valid declaration can still
    carry a warning when it uses a construct that cannot be represented as a
    version constraint (for example a direct URL reference).
    """
    candidate = declaration.strip()

    if not candidate:
        return None, None

    try:
        requirement = Requirement(candidate)
    except InvalidRequirement as error:
        message = (
            f"{source_manifest}: could not parse dependency declaration "
            f"{candidate!r}: {error}"
        )
        return None, message

    dependency = _build_record(
        requirement,
        raw_declaration=candidate,
        source_manifest=source_manifest,
        dependency_type=dependency_type,
        optional_group=optional_group,
    )

    warning = None
    if requirement.url:
        warning = (
            f"{source_manifest}: dependency {candidate!r} uses a direct URL "
            "reference; no version constraint was recorded"
        )

    return dependency, warning


def parse_requirements_txt(
    content: str,
    source_manifest: str = REQUIREMENTS_FILENAME,
) -> ParseResult:
    """Parse the contents of a ``requirements.txt`` file.

    Blank lines, comments and line continuations are handled. Pip option lines
    (for example ``-r``, ``-c``, ``-e`` or ``--index-url``) are not package
    declarations and are reported as warnings instead of being misinterpreted.
    """
    dependencies: list[Dependency] = []
    warnings: list[str] = []

    for line_number, raw_line in _iter_logical_lines(content):
        line = _strip_inline_comment(raw_line).strip()

        if not line:
            continue

        if line.startswith("-"):
            warnings.append(_describe_option_warning(source_manifest, line_number, line))
            continue

        if "--hash" in line:
            warnings.append(
                f"{source_manifest} line {line_number}: hash-checking options are "
                f"not supported; declaration {line!r} was skipped"
            )
            continue

        dependency, warning = parse_requirement_string(
            line,
            source_manifest=source_manifest,
            dependency_type=REGULAR,
        )

        if warning is not None:
            warnings.append(warning)

        if dependency is not None:
            dependencies.append(dependency)

    return {"dependencies": dependencies, "warnings": warnings}


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


def _build_record(
    requirement: Requirement,
    *,
    raw_declaration: str,
    source_manifest: str,
    dependency_type: str,
    optional_group: str | None,
) -> Dependency:
    """Build the normalized dependency record shared by every parser."""
    constraint = str(requirement.specifier).strip() or None
    marker = str(requirement.marker) if requirement.marker is not None else None

    return {
        "name": requirement.name,
        "normalized_name": normalize_package_name(requirement.name),
        "version_constraint": constraint,
        "extras": sorted(requirement.extras),
        "environment_marker": marker,
        "dependency_type": dependency_type,
        "optional_group": optional_group,
        "source_manifest": source_manifest,
        "raw_declaration": raw_declaration,
    }


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


def _iter_logical_lines(content: str) -> list[tuple[int, str]]:
    """Join backslash line continuations and yield ``(line_number, text)``.

    The reported line number is the first physical line of the logical line so
    that warnings point at a useful location.
    """
    logical_lines: list[tuple[int, str]] = []
    buffer = ""
    start_line = 0

    for index, physical in enumerate(content.splitlines(), start=1):
        if not buffer:
            start_line = index

        if physical.rstrip().endswith("\\"):
            buffer += physical.rstrip()[:-1] + " "
            continue

        buffer += physical
        logical_lines.append((start_line, buffer))
        buffer = ""

    if buffer.strip():
        logical_lines.append((start_line, buffer))

    return logical_lines


def _strip_inline_comment(line: str) -> str:
    """Remove an inline ``#`` comment.

    A ``#`` only starts a comment when it is at the start of the line or
    preceded by whitespace. This keeps ``#`` characters that are part of a URL
    fragment intact.
    """
    for index, character in enumerate(line):
        if character == "#" and (index == 0 or line[index - 1].isspace()):
            return line[:index]

    return line


def _describe_option_warning(source_manifest: str, line_number: int, line: str) -> str:
    """Return a specific, human-readable warning for a pip option line."""
    lowered = line.lower()

    if lowered.startswith(("-r", "--requirement")):
        reason = "recursive requirements includes are not supported"
    elif lowered.startswith(("-c", "--constraint")):
        reason = "constraint files are not supported"
    elif lowered.startswith(("-e", "--editable")):
        reason = "editable/development installs are not supported"
    elif lowered.startswith(("-i", "--index-url", "--extra-index-url")):
        reason = "index configuration lines are not supported"
    else:
        reason = "pip option lines are not supported"

    return f"{source_manifest} line {line_number}: {reason}; {line!r} was skipped"
