"""Shared helpers for dependency manifest parsers.

The functions in this module convert PEP 508 declarations into the normalized
dependency record used by every manifest parser. They are pure helpers: no file
or network access happens here.
"""

from typing import Any

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

REGULAR = "regular"
OPTIONAL = "optional"

Dependency = dict[str, Any]
ParseResult = dict[str, Any]

__all__ = [
    "REGULAR",
    "OPTIONAL",
    "Dependency",
    "ParseResult",
    "normalize_package_name",
    "parse_requirement_string",
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
