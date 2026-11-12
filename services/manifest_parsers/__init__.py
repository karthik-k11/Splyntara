"""Registry and parsers for supported dependency manifest formats."""

from services.manifest_parsers.common import (
    OPTIONAL,
    REGULAR,
    Dependency,
    ParseResult,
    normalize_package_name,
    parse_requirement_string,
)
from services.manifest_parsers.pyproject import (
    PYPROJECT_FILENAME,
    parse_pyproject_toml,
)
from services.manifest_parsers.requirements import (
    REQUIREMENTS_FILENAME,
    parse_requirements_txt,
)

FORMAT_REQUIREMENTS = "requirements"
FORMAT_PYPROJECT = "pyproject"

# Manifest filename -> (format identifier, parser callable).
MANIFEST_PARSERS = {
    REQUIREMENTS_FILENAME: (FORMAT_REQUIREMENTS, parse_requirements_txt),
    PYPROJECT_FILENAME: (FORMAT_PYPROJECT, parse_pyproject_toml),
}

# Deterministic processing order for reproducible inventories.
MANIFEST_ORDER = (REQUIREMENTS_FILENAME, PYPROJECT_FILENAME)

__all__ = [
    "REQUIREMENTS_FILENAME",
    "PYPROJECT_FILENAME",
    "FORMAT_REQUIREMENTS",
    "FORMAT_PYPROJECT",
    "MANIFEST_PARSERS",
    "MANIFEST_ORDER",
    "REGULAR",
    "OPTIONAL",
    "Dependency",
    "ParseResult",
    "normalize_package_name",
    "parse_requirement_string",
    "parse_requirements_txt",
    "parse_pyproject_toml",
]
