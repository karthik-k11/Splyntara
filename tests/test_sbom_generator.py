"""Tests for CycloneDX SBOM generation."""

import json
from datetime import datetime, timezone
from pathlib import Path

from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonValidator

from services.dependency_discovery import STATUS_NO_MANIFESTS, STATUS_PARTIAL
from services.sbom_generator import (
    BOM_FORMAT,
    SPEC_VERSION,
    STATUS_EMPTY,
    STATUS_ERROR,
    STATUS_PARTIAL as SBOM_STATUS_PARTIAL,
    STATUS_SUCCESS,
    build_sbom,
    generate_sbom,
)


def _write(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def _validate(document):
    validator = JsonValidator(SchemaVersion.V1_5)
    error = validator.validate_str(json.dumps(document))
    assert error is None


def _component_by_purl(document, purl):
    return next(
        component
        for component in document.get("components", [])
        if component["purl"] == purl
    )


def _properties(component):
    return {
        (item["name"], item["value"])
        for item in component.get("properties", [])
    }


def test_generate_sbom_includes_components_metadata_and_dependencies(tmp_path):
    _write(tmp_path / "requirements.txt", "Flask>=3.1,<4.0\nrequests==2.31.0\n")
    _write(
        tmp_path / "pyproject.toml",
        """
[project]
name = "demo"
dependencies = ["requests>=3.0"]

[project.optional-dependencies]
dev = ["pytest>=8.0"]
""",
    )

    result = generate_sbom(tmp_path)

    assert result["status"] == SBOM_STATUS_PARTIAL
    assert result["source_status"] == STATUS_PARTIAL
    assert result["component_count"] == 3
    assert any("No supported Python lockfile" in item for item in result["warnings"])

    document = result["sbom"]
    assert document["bomFormat"] == BOM_FORMAT
    assert document["specVersion"] == SPEC_VERSION
    assert document["version"] == 1
    assert "timestamp" in document["metadata"]
    assert document["metadata"]["tools"] == {
        "components": [
            {
                "bom-ref": "splyntara:tool",
                "name": "Splyntara",
                "type": "application",
            }
        ]
    }
    assert document["metadata"]["component"]["type"] == "application"
    assert document["metadata"]["component"]["name"] == tmp_path.name
    assert document["serialNumber"].startswith("urn:uuid:")

    assert [component["purl"] for component in document["components"]] == [
        "pkg:pypi/flask",
        "pkg:pypi/pytest",
        "pkg:pypi/requests",
    ]

    requests_component = _component_by_purl(document, "pkg:pypi/requests")
    assert requests_component["bom-ref"] == "pkg:pypi/requests"
    assert requests_component["type"] == "library"
    assert requests_component["scope"] == "required"
    assert "version" not in requests_component

    properties = _properties(requests_component)
    assert ("splyntara:version_constraint", "==2.31.0") in properties
    assert ("splyntara:version_constraint", ">=3.0") in properties
    assert ("splyntara:source_manifest", "requirements.txt") in properties
    assert ("splyntara:source_manifest", "pyproject.toml") in properties
    assert ("splyntara:dependency_type", "regular") in properties

    pytest_component = _component_by_purl(document, "pkg:pypi/pytest")
    assert pytest_component["scope"] == "optional"
    assert ("splyntara:optional_group", "dev") in _properties(pytest_component)

    project_ref = document["metadata"]["component"]["bom-ref"]
    project_dependency = next(
        item for item in document["dependencies"] if item["ref"] == project_ref
    )
    assert set(project_dependency["dependsOn"]) == {
        "pkg:pypi/flask",
        "pkg:pypi/pytest",
        "pkg:pypi/requests",
    }

    _validate(document)


def test_generate_sbom_uses_supplied_timestamp(tmp_path):
    _write(tmp_path / "requirements.txt", "flask\n")
    timestamp = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)

    result = generate_sbom(tmp_path, timestamp=timestamp)

    assert result["sbom"]["metadata"]["timestamp"] == "2026-01-02T03:04:05+00:00"


def test_generate_sbom_handles_empty_directory(tmp_path):
    result = generate_sbom(tmp_path)

    assert result["status"] == STATUS_EMPTY
    assert result["source_status"] == STATUS_NO_MANIFESTS
    assert result["component_count"] == 0
    assert any("No supported Python lockfile" in item for item in result["warnings"])
    assert result["sbom"].get("components", []) == []
    assert result["sbom"]["bomFormat"] == BOM_FORMAT
    _validate(result["sbom"])


def test_generate_sbom_handles_empty_manifest(tmp_path):
    _write(tmp_path / "requirements.txt", "# no dependencies\n")

    result = generate_sbom(tmp_path)

    assert result["status"] == SBOM_STATUS_PARTIAL
    assert result["source_status"] == STATUS_PARTIAL
    assert result["component_count"] == 0
    _validate(result["sbom"])


def test_generate_sbom_handles_partial_discovery(tmp_path):
    _write(tmp_path / "pyproject.toml", "[project\ndependencies = [\n")

    result = generate_sbom(tmp_path)

    assert result["status"] == SBOM_STATUS_PARTIAL
    assert result["source_status"] == STATUS_PARTIAL
    assert result["component_count"] == 0
    assert any("malformed TOML" in warning for warning in result["warnings"])
    assert any(
        property_item["name"] == "splyntara:warning"
        and "malformed TOML" in property_item["value"]
        for property_item in result["sbom"]["metadata"]["properties"]
    )
    _validate(result["sbom"])


def test_generate_sbom_handles_missing_directory(tmp_path):
    missing = tmp_path / "does-not-exist"

    result = generate_sbom(missing)

    assert result["status"] == STATUS_ERROR
    assert result["sbom"] is None
    assert "could not access project directory" in result["error"]


def test_build_sbom_skips_invalid_inventory_entries():
    discovery_result = {
        "project_directory": "/demo",
        "project_name": "demo",
        "status": "success",
        "warnings": [],
        "inventory": [
            None,
            {},
            {"name": 123},
            {
                "name": "Requests",
                "normalized_name": "requests",
                "version_constraints": ">=2.31.0",
                "dependency_types": "regular",
                "source_manifests": "requirements.txt",
                "declarations": "invalid",
            },
        ],
    }

    result = build_sbom(discovery_result)

    assert result["status"] == SBOM_STATUS_PARTIAL
    assert result["component_count"] == 1
    assert len(result["warnings"]) == 4
    component = result["sbom"]["components"][0]
    assert component["purl"] == "pkg:pypi/requests"
    assert ("splyntara:version_constraint", ">=2.31.0") in _properties(component)
    _validate(result["sbom"])


def test_build_sbom_rejects_non_dictionary_discovery_result():
    result = build_sbom([])

    assert result["status"] == STATUS_ERROR
    assert result["sbom"] is None
    assert result["error"] == "dependency discovery result must be a dictionary"


def test_build_sbom_handles_non_list_inventory():
    result = build_sbom(
        {
            "project_directory": "/demo",
            "project_name": "demo",
            "status": "success",
            "inventory": "not-a-list",
            "warnings": [],
        }
    )

    assert result["status"] == SBOM_STATUS_PARTIAL
    assert result["component_count"] == 0
    assert result["warnings"] == [
        "inventory is not a list; no components were generated"
    ]
    _validate(result["sbom"])


def test_build_sbom_uses_explicit_resolved_version_only_when_present():
    result = build_sbom(
        {
            "project_directory": "/demo",
            "project_name": "demo",
            "status": "success",
            "inventory": [
                {
                    "name": "requests",
                    "normalized_name": "requests",
                    "version": "2.31.0",
                    "declarations": [],
                }
            ],
            "warnings": [],
        }
    )

    component = result["sbom"]["components"][0]
    assert component["version"] == "2.31.0"
    assert component["purl"] == "pkg:pypi/requests@2.31.0"
    assert component["bom-ref"] == "pkg:pypi/requests@2.31.0"
    _validate(result["sbom"])


def test_build_sbom_deduplicates_component_references():
    entry = {
        "name": "requests",
        "normalized_name": "requests",
        "declarations": [],
    }

    result = build_sbom(
        {
            "project_directory": "/demo",
            "project_name": "demo",
            "status": "success",
            "inventory": [entry, dict(entry)],
            "warnings": [],
        }
    )

    assert result["status"] == SBOM_STATUS_PARTIAL
    assert result["component_count"] == 1
    assert len(result["sbom"]["components"]) == 1
    assert any("duplicates component" in warning for warning in result["warnings"])
