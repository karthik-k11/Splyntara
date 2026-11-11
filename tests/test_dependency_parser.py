"""Tests for the dependency manifest parsers."""

from services.dependency_parser import (
    OPTIONAL,
    REGULAR,
    normalize_package_name,
    parse_pyproject_toml,
    parse_requirement_string,
    parse_requirements_txt,
)


def test_normalize_package_name_is_pep503_consistent():
    assert normalize_package_name("Flask") == "flask"
    assert normalize_package_name("Zope.Interface") == "zope-interface"
    assert normalize_package_name("my_package.name") == "my-package-name"


def test_parse_requirement_string_extracts_expected_fields():
    dependency, warning = parse_requirement_string(
        "requests>=2.31.0",
        source_manifest="requirements.txt",
    )

    assert warning is None
    assert dependency["name"] == "requests"
    assert dependency["normalized_name"] == "requests"
    assert dependency["version_constraint"] == ">=2.31.0"
    assert dependency["extras"] == []
    assert dependency["environment_marker"] is None
    assert dependency["dependency_type"] == REGULAR
    assert dependency["source_manifest"] == "requirements.txt"


def test_parse_requirement_string_without_constraint_is_explicitly_none():
    dependency, warning = parse_requirement_string(
        "requests",
        source_manifest="requirements.txt",
    )

    assert warning is None
    assert dependency["version_constraint"] is None


def test_parse_requirement_string_reports_invalid_declaration():
    dependency, warning = parse_requirement_string(
        "this is not valid!!",
        source_manifest="requirements.txt",
    )

    assert dependency is None
    assert warning is not None
    assert "could not parse" in warning


def test_parse_requirements_txt_parses_multiple_dependencies():
    content = "Flask>=3.1,<4.0\nrequests>=2.32.0\npackaging>=24.0\n"

    result = parse_requirements_txt(content)

    assert result["warnings"] == []
    assert [item["normalized_name"] for item in result["dependencies"]] == [
        "flask",
        "requests",
        "packaging",
    ]


def test_parse_requirements_txt_handles_comments_and_blank_lines():
    content = (
        "# a full-line comment\n"
        "\n"
        "requests>=2.31.0  # inline comment\n"
        "   \n"
        "flask\n"
    )

    result = parse_requirements_txt(content)

    assert result["warnings"] == []
    assert [item["normalized_name"] for item in result["dependencies"]] == [
        "requests",
        "flask",
    ]


def test_parse_requirements_txt_normalizes_compound_version_constraints():
    result = parse_requirements_txt("Flask>=3.1,<4.0\n")

    constraint = result["dependencies"][0]["version_constraint"]
    assert set(constraint.split(",")) == {">=3.1", "<4.0"}


def test_parse_requirements_txt_extracts_extras_and_environment_markers():
    content = 'uvicorn[standard]>=0.30.0; python_version >= "3.9"\n'

    result = parse_requirements_txt(content)
    dependency = result["dependencies"][0]

    assert dependency["normalized_name"] == "uvicorn"
    assert dependency["extras"] == ["standard"]
    assert dependency["environment_marker"] == 'python_version >= "3.9"'


def test_parse_requirements_txt_skips_invalid_declaration_with_warning():
    content = "requests>=2.31.0\nthis is not valid!!\nflask\n"

    result = parse_requirements_txt(content)

    assert [item["normalized_name"] for item in result["dependencies"]] == [
        "requests",
        "flask",
    ]
    assert len(result["warnings"]) == 1
    assert "could not parse" in result["warnings"][0]


def test_parse_requirements_txt_warns_about_pip_option_lines():
    content = "-r requirements-dev.txt\n--index-url https://example.com/simple\n"

    result = parse_requirements_txt(content)

    assert result["dependencies"] == []
    assert len(result["warnings"]) == 2
    assert "recursive requirements" in result["warnings"][0]
    assert "index configuration" in result["warnings"][1]


def test_parse_requirements_txt_warns_about_hash_options():
    content = "requests==2.31.0 --hash=sha256:deadbeef\n"

    result = parse_requirements_txt(content)

    assert result["dependencies"] == []
    assert len(result["warnings"]) == 1
    assert "hash-checking" in result["warnings"][0]


def test_parse_requirements_txt_joins_line_continuations():
    content = "requests>=2.31.0,\\\n    <3.0\n"

    result = parse_requirements_txt(content)

    assert len(result["dependencies"]) == 1
    assert result["dependencies"][0]["normalized_name"] == "requests"


def test_parse_requirements_txt_warns_about_direct_url_references():
    content = "mypkg @ https://example.com/mypkg-1.0.whl\n"

    result = parse_requirements_txt(content)

    assert len(result["dependencies"]) == 1
    assert result["dependencies"][0]["version_constraint"] is None
    assert len(result["warnings"]) == 1
    assert "direct URL" in result["warnings"][0]


def test_parse_requirements_txt_handles_empty_content():
    result = parse_requirements_txt("")

    assert result["dependencies"] == []
    assert result["warnings"] == []


def test_parse_pyproject_toml_reads_project_dependencies():
    content = """
[project]
name = "demo"
dependencies = [
    "Flask>=3.1,<4.0",
    "requests>=2.32.0",
]
"""

    result = parse_pyproject_toml(content)

    assert result["warnings"] == []
    assert [item["normalized_name"] for item in result["dependencies"]] == [
        "flask",
        "requests",
    ]
    assert all(item["dependency_type"] == REGULAR for item in result["dependencies"])
    assert all(
        item["source_manifest"] == "pyproject.toml"
        for item in result["dependencies"]
    )


def test_parse_pyproject_toml_reads_optional_dependencies():
    content = """
[project]
name = "demo"
dependencies = ["requests>=2.32.0"]

[project.optional-dependencies]
dev = ["pytest>=8.0", "ruff>=0.5"]
docs = ["sphinx>=7.0"]
"""

    result = parse_pyproject_toml(content)

    optional = [item for item in result["dependencies"] if item["dependency_type"] == OPTIONAL]
    assert {item["normalized_name"] for item in optional} == {"pytest", "ruff", "sphinx"}
    assert {item["optional_group"] for item in optional} == {"dev", "docs"}

    regular = [item for item in result["dependencies"] if item["dependency_type"] == REGULAR]
    assert [item["normalized_name"] for item in regular] == ["requests"]
    assert regular[0]["optional_group"] is None


def test_parse_pyproject_toml_handles_malformed_toml():
    content = "[project\ndependencies = [\n"

    result = parse_pyproject_toml(content)

    assert result["dependencies"] == []
    assert len(result["warnings"]) == 1
    assert "malformed TOML" in result["warnings"][0]


def test_parse_pyproject_toml_warns_when_project_table_is_missing():
    content = "[tool.something]\nkey = 'value'\n"

    result = parse_pyproject_toml(content)

    assert result["dependencies"] == []
    assert len(result["warnings"]) == 1
    assert "[project]" in result["warnings"][0]


def test_parse_pyproject_toml_warns_about_non_string_entries():
    content = """
[project]
name = "demo"
dependencies = ["requests>=2.0", 123]
"""

    result = parse_pyproject_toml(content)

    assert [item["normalized_name"] for item in result["dependencies"]] == ["requests"]
    assert len(result["warnings"]) == 1
    assert "non-string" in result["warnings"][0]


def test_parse_pyproject_toml_skips_invalid_declaration_with_warning():
    content = """
[project]
name = "demo"
dependencies = ["requests>=2.0", "not valid!!"]
"""

    result = parse_pyproject_toml(content)

    assert [item["normalized_name"] for item in result["dependencies"]] == ["requests"]
    assert len(result["warnings"]) == 1
    assert "could not parse" in result["warnings"][0]
