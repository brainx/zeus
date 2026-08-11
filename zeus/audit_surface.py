from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence

from zeus.audit_models import AuditCategory, AuditSurface
from zeus.audit_workspace import SnapshotManifestEntry

SECURITY_CONTROL_CATALOG_VERSION = "1.0.0"
SECURITY_CONTROL_IDS = frozenset(
    {"SEC-CI", "SEC-DEPS", "SEC-IAC", "SEC-NATIVE", "SEC-REPO", "SEC-WEB"}
)
_PATH_SAMPLE_LIMIT = 32
_PATH_SAMPLE_BYTES = 1024

_DEPENDENCY_MANIFESTS = frozenset(
    {
        "Cargo.lock",
        "Cargo.toml",
        "Gemfile",
        "Gemfile.lock",
        "Package.resolved",
        "Package.swift",
        "Pipfile",
        "Pipfile.lock",
        "build.gradle",
        "build.gradle.kts",
        "bun.lock",
        "bun.lockb",
        "composer.json",
        "composer.lock",
        "go.mod",
        "go.sum",
        "gradle.lockfile",
        "package-lock.json",
        "package.json",
        "pnpm-lock.yaml",
        "poetry.lock",
        "pom.xml",
        "pyproject.toml",
        "requirements.txt",
        "uv.lock",
        "yarn.lock",
    }
)
_CI_ROOT_FILES = frozenset(
    {
        ".gitlab-ci.yml",
        "Jenkinsfile",
        "azure-pipelines.yml",
        "bitbucket-pipelines.yml",
    }
)
_WEB_PATH_PARTS = frozenset(
    {"api", "controllers", "handlers", "http", "pages", "routes", "server", "views", "web"}
)
_WEB_SOURCE_SUFFIXES = frozenset(
    {".go", ".java", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".rs", ".ts", ".tsx"}
)
_WEB_FILE_STEMS = frozenset(
    {
        "api",
        "app",
        "application",
        "asgi",
        "http",
        "manage",
        "routes",
        "server",
        "urls",
        "web",
        "wsgi",
    }
)
_WEB_FILE_STEM_PREFIXES = ("api_", "http_", "web_")
_WEB_FILE_STEM_SUFFIXES = ("_api", "_controller", "_handler", "_routes", "_server")
_EXTENSION_ECOSYSTEMS = {
    ".c": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".go": "go",
    ".h": "c",
    ".hh": "cpp",
    ".hpp": "cpp",
    ".java": "java",
    ".js": "javascript",
    ".jsx": "javascript",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".php": "php",
    ".py": "python",
    ".rb": "ruby",
    ".rs": "rust",
    ".sh": "shell",
    ".swift": "swift",
    ".tf": "terraform",
    ".ts": "javascript",
    ".tsx": "javascript",
}
_MANIFEST_ECOSYSTEMS = {
    "Cargo.lock": "rust",
    "Cargo.toml": "rust",
    "Gemfile": "ruby",
    "Gemfile.lock": "ruby",
    "Package.resolved": "swift",
    "Package.swift": "swift",
    "Pipfile": "python",
    "Pipfile.lock": "python",
    "build.gradle": "java",
    "build.gradle.kts": "kotlin",
    "composer.json": "php",
    "composer.lock": "php",
    "go.mod": "go",
    "go.sum": "go",
    "package-lock.json": "javascript",
    "package.json": "javascript",
    "pnpm-lock.yaml": "javascript",
    "poetry.lock": "python",
    "pom.xml": "java",
    "pyproject.toml": "python",
    "requirements.txt": "python",
    "uv.lock": "python",
    "yarn.lock": "javascript",
}
_NATIVE_ECOSYSTEMS = frozenset({"c", "cpp", "go", "rust"})


class AuditSurfaceError(ValueError):
    pass


def _is_dependency_manifest(path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    return name in _DEPENDENCY_MANIFESTS or (
        name.startswith("requirements-") and name.endswith(".txt")
    )


def _is_ci_path(path: str) -> bool:
    return (
        path in _CI_ROOT_FILES
        or path.startswith(".github/workflows/")
        or path.startswith(".circleci/")
        or path.startswith(".buildkite/")
    )


def _is_iac_path(path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    parts = set(path.split("/"))
    return (
        name == "Dockerfile"
        or name.startswith("Dockerfile.")
        or name in {"compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml"}
        or name.endswith(".tf")
        or bool(parts.intersection({"charts", "helm", "k8s", "kubernetes"}))
    )


def _is_web_path(path: str) -> bool:
    parts = path.split("/")
    name = parts[-1]
    dot = name.rfind(".")
    suffix = name[dot:].lower() if dot >= 0 else ""
    stem = name[:dot].lower() if dot >= 0 else name.lower()
    return (
        bool(set(parts[:-1]).intersection(_WEB_PATH_PARTS))
        or name.startswith(("next.config.", "vite.config."))
        or (
            suffix in _WEB_SOURCE_SUFFIXES
            and (
                stem in _WEB_FILE_STEMS
                or stem.startswith(_WEB_FILE_STEM_PREFIXES)
                or stem.endswith(_WEB_FILE_STEM_SUFFIXES)
            )
        )
    )


def _ecosystem(path: str) -> str | None:
    name = path.rsplit("/", 1)[-1]
    manifest = _MANIFEST_ECOSYSTEMS.get(name)
    if manifest is not None:
        return manifest
    dot = name.rfind(".")
    return _EXTENSION_ECOSYSTEMS.get(name[dot:].lower()) if dot >= 0 else None


def _manifest_digest(entries: Sequence[SnapshotManifestEntry]) -> str:
    digest = hashlib.sha256()
    digest.update(b"[")
    seen: set[str] = set()
    for index, entry in enumerate(sorted(entries, key=lambda item: item.path)):
        if not isinstance(entry, SnapshotManifestEntry) or entry.path in seen:
            raise AuditSurfaceError("snapshot surface manifest is invalid")
        seen.add(entry.path)
        if index:
            digest.update(b",")
        digest.update(
            json.dumps(
                {
                    "git_mode": entry.git_mode,
                    "mode": entry.mode,
                    "path": entry.path,
                    "sha256": entry.sha256,
                    "size": entry.size,
                    "symlink_target": entry.symlink_target,
                },
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
        )
    digest.update(b"]")
    return digest.hexdigest()


def _sample(paths: set[str]) -> tuple[str, ...]:
    sample: list[str] = []
    used_bytes = 0
    for path in sorted(paths):
        path_bytes = len(path.encode("utf-8"))
        if path_bytes > _PATH_SAMPLE_BYTES - used_bytes:
            continue
        sample.append(path)
        used_bytes += path_bytes
        if len(sample) == _PATH_SAMPLE_LIMIT:
            break
    return tuple(sample)


def build_audit_surface(
    entries: Sequence[SnapshotManifestEntry],
    categories: frozenset[AuditCategory],
) -> AuditSurface:
    if (
        not isinstance(entries, Sequence)
        or not categories
        or not all(isinstance(category, AuditCategory) for category in categories)
    ):
        raise AuditSurfaceError("audit surface inputs are invalid")
    snapshot_digest = _manifest_digest(entries)
    ecosystems: set[str] = set()
    dependency_paths: set[str] = set()
    ci_paths: set[str] = set()
    iac_paths: set[str] = set()
    web_paths: set[str] = set()
    for entry in entries:
        path = entry.path
        detected = _ecosystem(path)
        if detected is not None:
            ecosystems.add(detected)
        if _is_dependency_manifest(path):
            dependency_paths.add(path)
        if _is_ci_path(path):
            ci_paths.add(path)
        if _is_iac_path(path):
            iac_paths.add(path)
        if _is_web_path(path):
            web_paths.add(path)

    controls: set[str] = set()
    if AuditCategory.security in categories:
        controls.add("SEC-REPO")
        if dependency_paths:
            controls.add("SEC-DEPS")
        if ci_paths:
            controls.add("SEC-CI")
        if iac_paths:
            controls.add("SEC-IAC")
        if web_paths:
            controls.add("SEC-WEB")
        if ecosystems.intersection(_NATIVE_ECOSYSTEMS):
            controls.add("SEC-NATIVE")

    return AuditSurface(
        catalog_version=SECURITY_CONTROL_CATALOG_VERSION,
        snapshot_digest=snapshot_digest,
        ecosystems=tuple(sorted(ecosystems)),
        dependency_manifests=_sample(dependency_paths),
        dependency_manifest_count=len(dependency_paths),
        ci_paths=_sample(ci_paths),
        ci_path_count=len(ci_paths),
        iac_paths=_sample(iac_paths),
        iac_path_count=len(iac_paths),
        web_paths=_sample(web_paths),
        web_path_count=len(web_paths),
        required_control_ids=tuple(sorted(controls)),
    )
