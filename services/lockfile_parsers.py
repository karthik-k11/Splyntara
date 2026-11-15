"""Static parsers for supported Python dependency lockfiles."""

from __future__ import annotations

import re
import tomllib
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from packaging.requirements import InvalidRequirement, Requirement
from packaging.version import InvalidVersion, Version

from services.manifest_parsers import normalize_package_name

UV_LOCK_FILENAME = "uv.lock"
POETRY_LOCK_FILENAME = "poetry.lock"
LOCKFILE_ORDER = (UV_LOCK_FILENAME, POETRY_LOCK_FILENAME)

_PACKAGE_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")

__all__ = [
    "UV_LOCK_FILENAME",
    "POETRY_LOCK_FILENAME",
    "LOCKFILE_ORDER",
    "LOCKFILE_PARSERS",
    "parse_uv_lock",
    "parse_poetry_lock",
]


def parse_uv_lock(content: str, source_lockfile: str = UV_LOCK_FILENAME) -> dict[str, Any]:
    """Parse package records and dependency edges from ``uv.lock`` TOML."""
    return _parse_lockfile(
        content,
        source_lockfile=source_lockfile,
        ecosystem="uv",
    )


def parse_poetry_lock(
    content: str,
    source_lockfile: str = POETRY_LOCK_FILENAME,
) -> dict[str, Any]:
    """Parse package records and dependency edges from ``poetry.lock`` TOML."""
    return _parse_lockfile(
        content,
        source_lockfile=source_lockfile,
        ecosystem="poetry",
    )


LOCKFILE_PARSERS = {
    UV_LOCK_FILENAME: ("uv", parse_uv_lock),
    POETRY_LOCK_FILENAME: ("poetry", parse_poetry_lock),
}


def _parse_lockfile(
    content: str,
    *,
    source_lockfile: str,
    ecosystem: str,
) -> dict[str, Any]:
    warnings: list[str] = []
    try:
        document = tomllib.loads(content)
    except tomllib.TOMLDecodeError as error:
        return {
            "status": "malformed",
            "packages": [],
            "warnings": [f"{source_lockfile}: malformed TOML: {error}"],
        }

    raw_packages = document.get("package")
    if not isinstance(raw_packages, list):
        if raw_packages is None and _is_empty_lockfile(document, ecosystem):
            return {
                "status": "empty",
                "packages": [],
                "warnings": [
                    f"{source_lockfile}: contains no package records; "
                    "no versions were resolved"
                ],
            }
        state = "empty" if not document else "unsupported"
        detail = "contains no package records" if state == "empty" else (
            "does not contain a supported package table"
        )
        return {
            "status": state,
            "packages": [],
            "warnings": [f"{source_lockfile}: {detail}; no versions were resolved"],
        }

    if ecosystem == "uv":
        lock_version = document.get("version")
        if (
            isinstance(lock_version, bool)
            or not isinstance(lock_version, int)
            or lock_version != 1
        ):
            return {
                "status": "unsupported",
                "packages": [],
                "warnings": [
                    f"{source_lockfile}: unsupported uv lockfile version; "
                    "no versions were resolved"
                ],
            }
    if ecosystem == "poetry":
        metadata = document.get("metadata")
        lock_version = (
            metadata.get("lock-version") if isinstance(metadata, dict) else None
        )
        if (
            not isinstance(lock_version, str)
            or re.fullmatch(r"[12]\.\d+", lock_version) is None
        ):
            return {
                "status": "unsupported",
                "packages": [],
                "warnings": [
                    f"{source_lockfile}: unsupported Poetry lockfile version; "
                    "no versions were resolved"
                ],
            }

    if not raw_packages:
        return {
            "status": "empty",
            "packages": [],
            "warnings": [
                f"{source_lockfile}: contains no package records; no versions were resolved"
            ],
        }

    packages: list[dict[str, Any]] = []
    for index, raw_package in enumerate(raw_packages):
        if not isinstance(raw_package, dict):
            warnings.append(
                f"{source_lockfile}: package record {index} is not a table; it was skipped"
            )
            continue

        name = raw_package.get("name")
        version = raw_package.get("version")
        if not isinstance(name, str) or not name.strip():
            warnings.append(
                f"{source_lockfile}: package record {index} has no valid name; it was skipped"
            )
            continue
        if not isinstance(version, str) or not _is_valid_version(version.strip()):
            warnings.append(
                f"{source_lockfile}: package {name!r} has no valid exact version; "
                "it was skipped"
            )
            continue

        normalized_name = normalize_package_name(name.strip())
        dependencies = _uv_relationships(
            raw_package,
            source_lockfile=source_lockfile,
            package_name=normalized_name,
            warnings=warnings,
        ) if ecosystem == "uv" else _poetry_dependencies(
            raw_package.get("dependencies"),
            source_lockfile=source_lockfile,
            package_name=normalized_name,
            warnings=warnings,
        )

        if ecosystem == "uv":
            source = _uv_source(raw_package.get("source"))
            metadata = _uv_metadata(raw_package)
        else:
            source = _poetry_source(raw_package.get("source"))
            metadata = _poetry_metadata(raw_package)

        packages.append(
            {
                "name": name.strip(),
                "normalized_name": normalized_name,
                "version": version.strip(),
                "package_source": source,
                "is_project_root": ecosystem == "uv" and _is_uv_project_root(source),
                "dependency_relationships": dependencies,
                "lockfile_metadata": metadata,
            }
        )

    status = "parsed" if not warnings else "partial"
    if not packages:
        status = "unsupported"
        if not warnings:
            warnings.append(
                f"{source_lockfile}: no usable package records were found"
            )

    return {"status": status, "packages": packages, "warnings": warnings}


def _is_empty_lockfile(document: dict[str, Any], ecosystem: str) -> bool:
    if ecosystem == "uv":
        version = document.get("version")
        return (
            isinstance(version, int)
            and not isinstance(version, bool)
            and version == 1
            and set(document).issubset({"version", "revision", "requires-python"})
        )

    metadata = document.get("metadata")
    if set(document) != {"metadata"} or not isinstance(metadata, dict):
        return False
    lock_version = metadata.get("lock-version")
    return (
        isinstance(lock_version, str)
        and re.fullmatch(r"[12]\.\d+", lock_version) is not None
    )


def _uv_dependencies(
    value: Any,
    *,
    source_lockfile: str,
    package_name: str,
    warnings: list[str],
) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list):
        warnings.append(
            f"{source_lockfile}: dependencies for {package_name} are not a list"
        )
        return []

    dependencies: list[dict[str, Any]] = []
    for entry in value:
        if isinstance(entry, str):
            try:
                requirement = Requirement(entry)
            except InvalidRequirement:
                dependency_name = _extract_name(entry)
                if dependency_name is None:
                    warnings.append(
                        f"{source_lockfile}: dependency entry for {package_name} "
                        "could not be parsed"
                    )
                    continue
                warnings.append(
                    f"{source_lockfile}: dependency entry {entry!r} for "
                    f"{package_name} was only partially parsed"
                )
                dependency = {
                    "name": dependency_name,
                    "normalized_name": normalize_package_name(dependency_name),
                }
            else:
                dependency = {
                    "name": requirement.name,
                    "normalized_name": normalize_package_name(requirement.name),
                    "version_constraint": str(requirement.specifier) or None,
                }
        elif isinstance(entry, dict):
            name = entry.get("name")
            if not isinstance(name, str) or not name.strip():
                warnings.append(
                    f"{source_lockfile}: dependency entry for {package_name} "
                    "has no name; it was skipped"
                )
                continue
            dependency = {
                "name": name.strip(),
                "normalized_name": normalize_package_name(name.strip()),
            }
            _copy_string(entry, "version", dependency, "version_constraint")
            _copy_string(entry, "marker", dependency)
            _copy_string(entry, "extra", dependency)
        else:
            warnings.append(
                f"{source_lockfile}: dependency entry for {package_name} "
                "has an unsupported shape; it was skipped"
            )
            continue
        dependencies.append(dependency)

    return _dedupe_relationships(dependencies)


def _uv_relationships(
    package: dict[str, Any],
    *,
    source_lockfile: str,
    package_name: str,
    warnings: list[str],
) -> list[dict[str, Any]]:
    dependencies = _uv_dependencies(
        package.get("dependencies"),
        source_lockfile=source_lockfile,
        package_name=package_name,
        warnings=warnings,
    )
    optional_dependencies = package.get("optional-dependencies")
    if optional_dependencies is not None:
        if not isinstance(optional_dependencies, dict):
            warnings.append(
                f"{source_lockfile}: optional dependencies for {package_name} "
                "are not a table"
            )
        else:
            for group, entries in optional_dependencies.items():
                optional = _uv_dependencies(
                    entries,
                    source_lockfile=source_lockfile,
                    package_name=package_name,
                    warnings=warnings,
                )
                for dependency in optional:
                    dependency["optional_group"] = str(group)
                dependencies.extend(optional)

    dev_dependencies = package.get("dev-dependencies")
    if dev_dependencies is not None:
        development = _uv_dependencies(
            dev_dependencies,
            source_lockfile=source_lockfile,
            package_name=package_name,
            warnings=warnings,
        )
        for dependency in development:
            dependency["optional_group"] = "dev"
        dependencies.extend(development)

    return _dedupe_relationships(dependencies)


def _poetry_dependencies(
    value: Any,
    *,
    source_lockfile: str,
    package_name: str,
    warnings: list[str],
) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, dict):
        warnings.append(
            f"{source_lockfile}: dependencies for {package_name} are not a table"
        )
        return []

    dependencies: list[dict[str, Any]] = []
    for raw_name, specifier in value.items():
        if not isinstance(raw_name, str) or not raw_name.strip():
            warnings.append(
                f"{source_lockfile}: dependency entry for {package_name} "
                "has no valid name; it was skipped"
            )
            continue

        dependency = {
            "name": raw_name.strip(),
            "normalized_name": normalize_package_name(raw_name.strip()),
        }
        if isinstance(specifier, str):
            if specifier.strip() not in {"", "*"}:
                dependency["version_constraint"] = specifier.strip()
        elif isinstance(specifier, dict):
            _copy_string(specifier, "version", dependency, "version_constraint")
            _copy_string(specifier, "markers", dependency, "marker")
            extras = specifier.get("extras")
            if isinstance(extras, list):
                dependency["extras"] = sorted(
                    item.strip() for item in extras
                    if isinstance(item, str) and item.strip()
                )
        elif specifier is not None:
            warnings.append(
                f"{source_lockfile}: dependency {raw_name!r} for {package_name} "
                "has an unsupported shape; it was skipped"
            )
            continue
        dependencies.append(dependency)

    return _dedupe_relationships(dependencies)


def _uv_source(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict) or not value:
        return None
    kind_keys = ("registry", "git", "url", "editable", "virtual", "directory")
    kind = next((key for key in kind_keys if key in value), next(iter(value)))
    source: dict[str, Any] = {"kind": str(kind)}
    for key, item in value.items():
        if isinstance(item, str) and item.strip():
            clean_value = (
                _sanitize_url(item.strip()) if _looks_like_url(item) else item.strip()
            )
            if key == kind:
                source["location"] = clean_value
            else:
                source[str(key)] = clean_value
        elif isinstance(item, dict):
            for nested_key, nested_value in item.items():
                if isinstance(nested_value, str) and nested_value.strip():
                    source[str(nested_key)] = (
                        _sanitize_url(nested_value.strip())
                        if _looks_like_url(nested_value)
                        else nested_value.strip()
                    )
    return source


def _is_uv_project_root(source: dict[str, Any] | None) -> bool:
    if not source or source.get("kind") not in {"editable", "virtual"}:
        return False
    location = source.get("location")
    return (
        isinstance(location, str)
        and location.replace("\\", "/").rstrip("/") == "."
    )


def _poetry_source(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict) or not value:
        return None
    source = {
        str(key): _sanitize_url(item.strip())
        if isinstance(item, str) and _looks_like_url(item)
        else item.strip()
        if isinstance(item, str)
        else item
        for key, item in value.items()
        if isinstance(item, (str, int, bool))
    }
    return source or None


def _uv_metadata(package: dict[str, Any]) -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    for key in ("resolution-markers", "requires-python"):
        value = package.get(key)
        if isinstance(value, str) and value.strip():
            metadata[key.replace("-", "_")] = value.strip()
    artifacts: list[dict[str, Any]] = []
    for artifact_key in ("sdist", "wheels"):
        raw_artifacts = package.get(artifact_key)
        if isinstance(raw_artifacts, dict):
            raw_artifacts = [raw_artifacts]
        if not isinstance(raw_artifacts, list):
            continue
        for artifact in raw_artifacts:
            if not isinstance(artifact, dict):
                continue
            clean: dict[str, Any] = {"kind": artifact_key}
            for key in ("url", "hash", "size", "upload-time"):
                value = artifact.get(key)
                if isinstance(value, str) and value.strip():
                    clean[key.replace("-", "_")] = (
                        _sanitize_url(value.strip()) if key == "url" else value.strip()
                    )
                elif isinstance(value, int) and not isinstance(value, bool):
                    clean[key] = value
            if len(clean) > 1:
                artifacts.append(clean)
    if artifacts:
        metadata["artifacts"] = artifacts
    return metadata


def _poetry_metadata(package: dict[str, Any]) -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    for key in ("python-versions", "groups", "category", "optional"):
        value = package.get(key)
        if isinstance(value, (str, bool)):
            metadata[key.replace("-", "_")] = value
        elif isinstance(value, list):
            metadata[key.replace("-", "_")] = [
                item for item in value if isinstance(item, str)
            ]
    files = package.get("files")
    if isinstance(files, list):
        metadata["files"] = [
            {
                key: value
                for key, value in item.items()
                if key in {"file", "hash"} and isinstance(value, str)
            }
            for item in files
            if isinstance(item, dict)
        ]
    return metadata


def _copy_string(
    source: dict[str, Any],
    source_key: str,
    destination: dict[str, Any],
    destination_key: str | None = None,
) -> None:
    value = source.get(source_key)
    if isinstance(value, str) and value.strip():
        destination[destination_key or source_key] = value.strip()


def _extract_name(value: str) -> str | None:
    match = _PACKAGE_NAME.match(value)
    return match.group(1) if match is not None else None


def _is_valid_version(value: str) -> bool:
    try:
        Version(value)
    except InvalidVersion:
        return False
    return True


def _looks_like_url(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return urlsplit(value).scheme.lower() in {"http", "https", "ssh", "git"}
    except ValueError:
        return False


def _sanitize_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return value

    netloc = parsed.netloc.rsplit("@", 1)[-1]
    query = [
        (key, "[redacted]" if re.search(r"token|password|secret|credential|auth|key", key, re.I) else item)
        for key, item in parse_qsl(parsed.query, keep_blank_values=True)
    ]
    return urlunsplit(
        (parsed.scheme, netloc, parsed.path, urlencode(query), parsed.fragment)
    )


def _dedupe_relationships(
    dependencies: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    seen: set[tuple[Any, ...]] = set()
    result: list[dict[str, Any]] = []
    for dependency in dependencies:
        signature = tuple(
            (key, repr(value)) for key, value in sorted(dependency.items())
        )
        if signature not in seen:
            seen.add(signature)
            result.append(dependency)
    return result
