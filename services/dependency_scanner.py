"""Backward-compatible facade for the dependency discovery engine.

The implementation now lives in :mod:`services.dependency_discovery`. This
module keeps the original import paths working for existing callers and tests.
"""

from services.dependency_discovery import (
    FORMAT_PYPROJECT,
    FORMAT_REQUIREMENTS,
    STATUS_ERROR,
    STATUS_NO_MANIFESTS,
    STATUS_PARTIAL,
    STATUS_SUCCESS,
    ScanResult,
    detect_manifests,
    discover_dependencies,
    scan_project,
)

__all__ = [
    "FORMAT_REQUIREMENTS",
    "FORMAT_PYPROJECT",
    "STATUS_SUCCESS",
    "STATUS_PARTIAL",
    "STATUS_NO_MANIFESTS",
    "STATUS_ERROR",
    "ScanResult",
    "detect_manifests",
    "discover_dependencies",
    "scan_project",
]
