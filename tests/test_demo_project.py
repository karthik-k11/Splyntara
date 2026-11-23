"""Release checks for the bundled demo project."""

from pathlib import Path

from services.dependency_discovery import STATUS_SUCCESS, discover_dependencies
from services.sbom_generator import STATUS_SUCCESS as SBOM_STATUS_SUCCESS, generate_sbom

DEMO_PROJECT = Path(__file__).resolve().parents[1] / "examples" / "demo_project"


def test_demo_project_discovers_expected_dependencies():
    result = discover_dependencies(DEMO_PROJECT)

    assert result["status"] == STATUS_SUCCESS
    assert result["resolution"]["status"] == "resolved"
    assert result["dependency_count"] == 2
    assert result["resolved_dependency_count"] == 2
    assert {
        entry["normalized_name"] for entry in result["inventory"]
    } == {"click", "colorama"}
    assert {
        entry["version"] for entry in result["inventory"]
    } == {"8.1.8", "0.4.6"}


def test_demo_project_generates_cyclonedx_sbom_offline():
    result = generate_sbom(DEMO_PROJECT)

    assert result["status"] == SBOM_STATUS_SUCCESS
    assert result["component_count"] == 2
    assert result["sbom"]["bomFormat"] == "CycloneDX"
    assert result["sbom"]["specVersion"] == "1.5"
    assert {
        component["version"] for component in result["sbom"]["components"]
    } == {"8.1.8", "0.4.6"}
