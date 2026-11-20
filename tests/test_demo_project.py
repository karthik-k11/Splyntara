"""Release checks for the bundled demo project."""

from pathlib import Path

from services.dependency_discovery import STATUS_PARTIAL, discover_dependencies
from services.sbom_generator import STATUS_PARTIAL as SBOM_STATUS_PARTIAL, generate_sbom

DEMO_PROJECT = Path(__file__).resolve().parents[1] / "examples" / "demo_project"


def test_demo_project_discovers_expected_dependencies():
    result = discover_dependencies(DEMO_PROJECT)

    assert result["status"] == STATUS_PARTIAL
    assert result["resolution"]["status"] == "missing"
    assert result["dependency_count"] == 2
    assert {
        entry["normalized_name"] for entry in result["inventory"]
    } == {"click", "colorama"}


def test_demo_project_generates_cyclonedx_sbom_offline():
    result = generate_sbom(DEMO_PROJECT)

    assert result["status"] == SBOM_STATUS_PARTIAL
    assert result["component_count"] == 2
    assert result["sbom"]["bomFormat"] == "CycloneDX"
    assert result["sbom"]["specVersion"] == "1.5"
