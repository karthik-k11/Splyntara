"""Parser for ``requirements.txt`` dependency manifests."""

from services.manifest_parsers.common import (
    REGULAR,
    Dependency,
    ParseResult,
    parse_requirement_string,
)

REQUIREMENTS_FILENAME = "requirements.txt"

__all__ = [
    "REQUIREMENTS_FILENAME",
    "parse_requirements_txt",
]


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
