"""CycloneDX SBOM generation from a discovered dependency inventory.

This service deliberately consumes the normalized output of
:mod:`services.dependency_discovery` rather than reading manifests itself. It
uses the CycloneDX model and JSON serializer so the generated document follows
the published schema.

Only declared version constraints are known at this stage. They are recorded as
component properties and are never promoted to a resolved component version.
"""

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cyclonedx.model import Property
from cyclonedx.model.bom import Bom, BomMetaData
from cyclonedx.model.bom_ref import BomRef
from cyclonedx.model.component import Component, ComponentScope, ComponentType
from cyclonedx.model.dependency import Dependency
from cyclonedx.model.tool import ToolRepository
from cyclonedx.output import make_outputter
from cyclonedx.schema import OutputFormat, SchemaVersion
from packageurl import PackageURL

from services.dependency_discovery import (
    STATUS_ERROR as DISCOVERY_STATUS_ERROR,
    STATUS_PARTIAL as DISCOVERY_STATUS_PARTIAL,
    discover_dependencies,
)
from services.manifest_parsers import normalize_package_name

BOM_FORMAT = "CycloneDX"
SPEC_VERSION = "1.5"
PYPI_ECOSYSTEM = "pypi"
TOOL_NAME = "Splyntara"

STATUS_SUCCESS = "success"
STATUS_PARTIAL = "partial"
STATUS_EMPTY = "empty"
STATUS_ERROR = "error"

SbomResult = dict[str, Any]

__all__ = [
    "BOM_FORMAT",
    "SPEC_VERSION",
    "PYPI_ECOSYSTEM",
    "STATUS_SUCCESS",
    "STATUS_PARTIAL",
    "STATUS_EMPTY",
    "STATUS_ERROR",
    "SbomResult",
    "generate_sbom",
    "build_sbom",
]


def generate_sbom(
    project_directory: str | Path,
    *,
    timestamp: datetime | None = None,
) -> SbomResult:
    """Discover dependencies in ``project_directory`` and generate an SBOM.

    Returns a stable result wrapper containing the CycloneDX document under
    ``sbom``. Discovery failures return ``status == "error"`` instead of
    raising, so API callers receive a consistent shape.
    """
    discovery_result = discover_dependencies(project_directory)
    return build_sbom(discovery_result, timestamp=timestamp)


def build_sbom(
    discovery_result: dict[str, Any],
    *,
    timestamp: datetime | None = None,
) -> SbomResult:
    """Build a CycloneDX SBOM from a dependency discovery result.

    Invalid inventory entries are skipped with warnings instead of aborting the
    whole document. Missing or empty inventories still produce a valid SBOM
    with no components.
    """
    if not isinstance(discovery_result, dict):
        return _error_result(
            "dependency discovery result must be a dictionary",
            project_directory="",
            project_name="",
        )

    project_directory = _string_or_empty(discovery_result.get("project_directory"))
    project_name = _string_or_empty(discovery_result.get("project_name"))
    source_status = _string_or_empty(discovery_result.get("status"))
    source_warnings = _string_list(discovery_result.get("warnings"))

    if source_status == DISCOVERY_STATUS_ERROR:
        message = source_warnings[0] if source_warnings else "dependency discovery failed"
        return _error_result(
            message,
            project_directory=project_directory,
            project_name=project_name,
            warnings=source_warnings,
        )

    try:
        document, generation_warnings = _build_document(
            discovery_result,
            project_directory=project_directory,
            project_name=project_name,
            source_status=source_status,
            source_warnings=source_warnings,
            timestamp=timestamp,
        )
    except Exception:  # noqa: BLE001 - convert serializer failures to a result
        message = "could not generate SBOM"
        return _error_result(
            message,
            project_directory=project_directory,
            project_name=project_name,
            warnings=source_warnings + [message],
        )

    warnings = source_warnings + generation_warnings
    component_count = len(document.get("components", []))

    if generation_warnings or source_status == DISCOVERY_STATUS_PARTIAL:
        status = STATUS_PARTIAL
    elif component_count == 0:
        status = STATUS_EMPTY
    else:
        status = STATUS_SUCCESS

    return {
        "status": status,
        "source_status": source_status,
        "project_directory": project_directory,
        "project_name": project_name,
        "component_count": component_count,
        "warnings": warnings,
        "sbom": document,
    }


def _build_document(
    discovery_result: dict[str, Any],
    *,
    project_directory: str,
    project_name: str,
    source_status: str,
    source_warnings: list[str],
    timestamp: datetime | None,
) -> tuple[dict[str, Any], list[str]]:
    """Build and serialize the CycloneDX document."""
    warnings: list[str] = []
    components: list[Component] = []
    seen_refs: set[str] = set()

    inventory = discovery_result.get("inventory")

    if inventory is None:
        entries: list[Any] = []
    elif not isinstance(inventory, list):
        warnings.append("inventory is not a list; no components were generated")
        entries = []
    else:
        entries = inventory

    for index, entry in enumerate(entries):
        component, component_warnings = _component_from_entry(entry, index=index)
        warnings.extend(component_warnings)

        if component is None:
            continue

        reference = str(component.bom_ref)

        if reference in seen_refs:
            warnings.append(
                f"inventory entry {index} duplicates component {reference!r}; "
                "it was skipped"
            )
            continue

        seen_refs.add(reference)
        components.append(component)

    components.sort(key=lambda item: str(item.bom_ref))

    resolved_project_name = project_name or _project_name_from_directory(project_directory)
    project_component = Component(
        name=resolved_project_name,
        type=ComponentType.APPLICATION,
        bom_ref=_project_bom_ref(resolved_project_name),
    )

    metadata_properties = [
        Property(name="splyntara:discovery_status", value=source_status or "unknown"),
        Property(name="splyntara:component_count", value=str(len(components))),
        Property(
            name="splyntara:version_policy",
            value="declared constraints only; resolved versions are not invented",
        ),
    ]

    if project_directory:
        metadata_properties.append(
            Property(name="splyntara:project_directory", value=project_directory)
        )

    for warning in source_warnings + warnings:
        metadata_properties.append(Property(name="splyntara:warning", value=warning))

    tool_component = Component(
        name=TOOL_NAME,
        type=ComponentType.APPLICATION,
        bom_ref=BomRef("splyntara:tool"),
    )
    metadata = BomMetaData(
        tools=ToolRepository(components=[tool_component]),
        component=project_component,
        properties=metadata_properties,
        timestamp=timestamp or datetime.now(timezone.utc),
    )

    project_dependency = Dependency(
        ref=project_component.bom_ref,
        dependencies=[Dependency(ref=component.bom_ref) for component in components],
    )

    bom = Bom(
        components=components,
        metadata=metadata,
        dependencies=[project_dependency],
    )

    outputter = make_outputter(bom, OutputFormat.JSON, SchemaVersion.V1_5)
    document = json.loads(outputter.output_as_string())

    return document, warnings


def _component_from_entry(
    entry: Any,
    *,
    index: int,
) -> tuple[Component | None, list[str]]:
    """Convert one inventory entry into a CycloneDX component."""
    warnings: list[str] = []

    if not isinstance(entry, dict):
        return None, [f"inventory entry {index} is not an object; it was skipped"]

    raw_name = entry.get("name")
    normalized_name = entry.get("normalized_name")

    if isinstance(normalized_name, str) and normalized_name.strip():
        package_name = normalized_name.strip()
    elif isinstance(raw_name, str) and raw_name.strip():
        package_name = normalize_package_name(raw_name.strip())
    else:
        return None, [
            f"inventory entry {index} has no usable package name; it was skipped"
        ]

    display_name = raw_name.strip() if isinstance(raw_name, str) and raw_name.strip() else package_name

    declarations = entry.get("declarations")
    if not isinstance(declarations, list):
        warnings.append(
            f"inventory entry {index} ({package_name!r}) has invalid declarations; "
            "declaration metadata was ignored"
        )
        declarations = []

    version = entry.get("version")
    resolved_version = version.strip() if isinstance(version, str) and version.strip() else None

    try:
        purl = PackageURL(
            type=PYPI_ECOSYSTEM,
            name=package_name,
            version=resolved_version,
        )
    except Exception:  # noqa: BLE001 - malformed package identifiers are skipped
        return None, [
            f"inventory entry {index} ({package_name!r}) has an invalid package "
            "identifier; it was skipped"
        ]

    reference = BomRef(str(purl))
    properties = _component_properties(entry, declarations)

    dependency_types = _string_list(entry.get("dependency_types"))
    scope = (
        ComponentScope.OPTIONAL
        if dependency_types == ["optional"]
        else ComponentScope.REQUIRED
    )

    component = Component(
        name=display_name,
        type=ComponentType.LIBRARY,
        bom_ref=reference,
        version=resolved_version,
        scope=scope,
        purl=purl,
        properties=properties,
    )

    return component, warnings


def _component_properties(
    entry: dict[str, Any],
    declarations: list[Any],
) -> list[Property]:
    """Build namespaced CycloneDX properties for one inventory entry."""
    version_constraints = _string_list(
        entry.get("version_constraints"),
        fallback=entry.get("version_constraint"),
    )
    dependency_types = _string_list(entry.get("dependency_types"))
    source_manifests = _string_list(entry.get("source_manifests"))
    optional_groups = _string_list(entry.get("optional_groups"))
    environment_markers: list[str] = []
    extras: list[str] = []
    raw_declarations: list[str] = []

    for declaration in declarations:
        if not isinstance(declaration, dict):
            continue

        version_constraints.extend(
            _string_list(declaration.get("version_constraint"))
        )
        dependency_types.extend(_string_list(declaration.get("dependency_type")))
        source_manifests.extend(_string_list(declaration.get("source_manifest")))
        optional_groups.extend(_string_list(declaration.get("optional_group")))
        environment_markers.extend(
            _string_list(declaration.get("environment_marker"))
        )
        extras.extend(_string_list(declaration.get("extras")))
        raw_declarations.extend(_string_list(declaration.get("raw_declaration")))

    property_values = (
        ("splyntara:version_constraint", version_constraints),
        ("splyntara:dependency_type", dependency_types),
        ("splyntara:source_manifest", source_manifests),
        ("splyntara:optional_group", optional_groups),
        ("splyntara:environment_marker", environment_markers),
        ("splyntara:extras", extras),
        ("splyntara:raw_declaration", raw_declarations),
    )

    properties: list[Property] = []

    for name, values in property_values:
        for value in sorted(set(values)):
            properties.append(Property(name=name, value=value))

    properties.append(
        Property(name="splyntara:declaration_count", value=str(len(declarations)))
    )

    return properties


def _string_list(value: Any, *, fallback: Any = None) -> list[str]:
    """Return a clean list of non-empty strings from a scalar or list."""
    values: list[Any] = []

    if isinstance(value, str):
        values.append(value)
    elif isinstance(value, list):
        values.extend(value)

    if fallback is not None:
        if isinstance(fallback, str):
            values.append(fallback)
        elif isinstance(fallback, list):
            values.extend(fallback)

    return [item.strip() for item in values if isinstance(item, str) and item.strip()]


def _string_or_empty(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _project_name_from_directory(project_directory: str) -> str:
    if not project_directory:
        return "unknown-project"

    return Path(project_directory).name or "unknown-project"


def _project_bom_ref(project_name: str) -> BomRef:
    slug = re.sub(r"[^a-z0-9._-]+", "-", project_name.lower()).strip("-")
    return BomRef(f"splyntara:project:{slug or 'project'}")


def _error_result(
    message: str,
    *,
    project_directory: str,
    project_name: str,
    warnings: list[str] | None = None,
) -> SbomResult:
    combined = list(warnings or [])
    if message not in combined:
        combined.insert(0, message)

    return {
        "status": STATUS_ERROR,
        "source_status": DISCOVERY_STATUS_ERROR,
        "project_directory": project_directory,
        "project_name": project_name,
        "component_count": 0,
        "warnings": combined,
        "sbom": None,
        "error": message,
    }
