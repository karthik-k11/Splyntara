"""Backward-compatible facade for the modular manifest parsers.

The implementation now lives in :mod:`services.manifest_parsers`. This module
keeps the original import paths working for existing callers and tests.
"""

from services.manifest_parsers import (
    OPTIONAL,
    PYPROJECT_FILENAME,
    REGULAR,
    REQUIREMENTS_FILENAME,
    Dependency,
    ParseResult,
    normalize_package_name,
    parse_pyproject_toml,
    parse_requirement_string,
    parse_requirements_txt,
)

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
