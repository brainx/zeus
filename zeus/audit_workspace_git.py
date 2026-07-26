from __future__ import annotations

import hashlib
import os
import shutil
import subprocess  # nosec B404
import tempfile
from dataclasses import replace
from pathlib import Path

from zeus.audit_models import HARD_LIMITS, AuditLimits
from zeus.audit_workspace_core import (
    _DISCOVERY_OUTPUT_BYTES,
    _IGNORE_POLICY_BLOB_BYTES,
    _IGNORE_POLICY_MAX_DEPTH,
    _IGNORE_POLICY_METADATA_BYTES,
    _IGNORE_POLICY_OUTPUT_BYTES,
    GIT_HARDENING_ARGUMENTS,
    AuditWorkspaceError,
    RepositoryChanges,
    RepositoryInspection,
    RepositoryLocation,
    _absolute_lexical_path,
    _bounded_deadline,
    _capture_repository_marker,
    _capture_safe_directory,
    _capture_safe_regular_file,
    _collect_bounded_process,
    _error,
    _parse_head_index_metadata,
    _parse_index_metadata,
    _parse_tree,
    _parse_untracked_metadata,
    _path_is_within,
    _single_line,
    _single_oid,
    _stop_process,
    _tracked_worktree_is_dirty,
    _TreeEntry,
    _validate_deadline,
    _validate_identity,
    _validate_relative_path_text,
    _validate_repository_metadata,
    audit_git_environment,
)


class _AuditWorkspaceGit:
    def __init__(self, git_executable: Path | None = None) -> None:
        if git_executable is None:
            resolved = shutil.which("git")
            if resolved is None:
                raise AuditWorkspaceError("Git executable is unavailable")
            candidate = Path(resolved)
        else:
            if not isinstance(git_executable, Path):
                raise AuditWorkspaceError("Git executable must be a pathlib.Path")
            candidate = git_executable
        try:
            self._git_executable = candidate.resolve(strict=True)
        except OSError as exc:
            raise AuditWorkspaceError("Git executable is unavailable") from exc
        if not self._git_executable.is_absolute():
            raise AuditWorkspaceError("Git executable did not resolve to an absolute path")
        self._git_identity = _capture_safe_regular_file(
            self._git_executable,
            "Git executable",
            allowed_owners=frozenset({0, os.geteuid()}),
            executable=True,
        )

    def _validate_git_executable(self) -> None:
        current = _capture_safe_regular_file(
            self._git_executable,
            "Git executable",
            allowed_owners=frozenset({0, os.geteuid()}),
            executable=True,
        )
        if current != self._git_identity:
            _error("Git executable binding changed")

    def _argv(
        self,
        cwd: Path,
        arguments: tuple[str, ...],
        *,
        literal_pathspecs: bool = True,
    ) -> tuple[str, ...]:
        return (
            str(self._git_executable),
            *(
                argument
                for argument in GIT_HARDENING_ARGUMENTS
                if literal_pathspecs or argument != "--literal-pathspecs"
            ),
            "-C",
            str(cwd),
            *arguments,
        )

    def _spawn(
        self,
        cwd: Path,
        arguments: tuple[str, ...],
        *,
        stdin: int,
        stderr: int,
        literal_pathspecs: bool = True,
    ) -> subprocess.Popen[bytes]:
        self._validate_git_executable()
        try:
            return subprocess.Popen(  # nosec B603
                self._argv(
                    cwd,
                    arguments,
                    literal_pathspecs=literal_pathspecs,
                ),
                cwd=cwd,
                env=audit_git_environment(),
                stdin=stdin,
                stdout=subprocess.PIPE,
                stderr=stderr,
                shell=False,
                close_fds=True,
                start_new_session=True,
                bufsize=0,
            )
        except OSError as exc:
            raise AuditWorkspaceError("Git process could not be started") from exc

    def _run(
        self,
        cwd: Path,
        arguments: tuple[str, ...],
        *,
        deadline: float,
        command_seconds: int,
        max_output_bytes: int,
        description: str,
        input_data: bytes | None = None,
        literal_pathspecs: bool = True,
    ) -> bytes:
        command_deadline = _bounded_deadline(deadline, command_seconds)
        process = self._spawn(
            cwd,
            arguments,
            stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            literal_pathspecs=literal_pathspecs,
        )
        if input_data is not None:
            if process.stdin is None:
                _stop_process(process)
                _error(f"{description} input pipe is unavailable")
            try:
                written = process.stdin.write(input_data)
                process.stdin.close()
            except (BrokenPipeError, OSError, ValueError) as exc:
                _stop_process(process)
                raise AuditWorkspaceError(f"{description} input could not be written") from exc
            if written != len(input_data):
                _stop_process(process)
                _error(f"{description} input could not be written completely")
        return _collect_bounded_process(
            process,
            deadline=command_deadline,
            max_output_bytes=max_output_bytes,
            description=description,
        )

    def committed_ignore_matches(
        self,
        location: RepositoryLocation,
        *,
        state_relative: Path,
        ignored_paths: tuple[str, ...],
        deadline: float,
    ) -> dict[str, str]:
        """Evaluate only bounded ignore rules loaded from the exact committed tree."""
        if not isinstance(location, RepositoryLocation):
            _error("repository location is invalid")
        if (
            not isinstance(state_relative, Path)
            or state_relative.is_absolute()
            or not state_relative.parts
            or len(state_relative.parts) > _IGNORE_POLICY_MAX_DEPTH
        ):
            _error("audit state ignore policy path is invalid")
        state_text = _validate_relative_path_text(
            state_relative.as_posix(),
            "audit state ignore policy path",
        )
        if state_text != state_relative.as_posix():
            _error("audit state ignore policy path is invalid")
        if not ignored_paths or len(set(ignored_paths)) != len(ignored_paths):
            _error("audit state ignore policy probes are invalid")
        for path in ignored_paths:
            _validate_relative_path_text(path.rstrip("/"), "audit state ignore policy probe")

        candidates = tuple(
            Path(*state_relative.parts[:depth], ".gitignore").as_posix()
            for depth in range(len(state_relative.parts) + 1)
        )
        self._validate_location_bindings(location)
        policy_limits = replace(
            HARD_LIMITS,
            snapshot_entries=len(candidates),
            snapshot_blob_bytes=_IGNORE_POLICY_BLOB_BYTES,
            git_metadata_bytes=_IGNORE_POLICY_METADATA_BYTES,
        )
        tree_output = self._run(
            location.root,
            (
                "ls-tree",
                "-z",
                "--full-tree",
                "--long",
                location.head,
                "--",
                *candidates,
            ),
            deadline=deadline,
            command_seconds=HARD_LIMITS.git_command_seconds,
            max_output_bytes=_IGNORE_POLICY_METADATA_BYTES,
            description="committed audit ignore metadata",
        )
        entries, _blob_bytes = _parse_tree(tree_output, policy_limits)
        if any(entry.path not in candidates for entry in entries):
            _error("committed audit ignore metadata returned an unexpected path")

        committed: dict[str, bytes] = {}
        for entry in entries:
            if entry.mode != "100644" or entry.size is None:
                _error("committed audit ignore policy must use regular non-executable files")
            data = self._run(
                location.root,
                ("cat-file", "blob", entry.object_id),
                deadline=deadline,
                command_seconds=HARD_LIMITS.git_command_seconds,
                max_output_bytes=max(1, entry.size),
                description="committed audit ignore policy",
            )
            if len(data) != entry.size or b"\0" in data:
                _error("committed audit ignore policy content is invalid")
            try:
                data.decode("utf-8", errors="strict")
            except UnicodeDecodeError as exc:
                raise AuditWorkspaceError(
                    "committed audit ignore policy is not valid UTF-8"
                ) from exc
            committed[entry.path] = data

        temporary_root = Path(tempfile.gettempdir()).resolve(strict=True)
        for boundary in (location.root, location.git_dir, location.common_git_dir):
            if _path_is_within(temporary_root, boundary):
                _error("audit ignore policy staging root overlaps repository boundaries")
        with tempfile.TemporaryDirectory(
            prefix="zeus-audit-ignore-",
            dir=temporary_root,
        ) as temporary:
            policy_root = Path(temporary)
            for path, data in committed.items():
                destination = policy_root / path
                destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                current = destination.parent
                while current != policy_root:
                    current.chmod(0o700)
                    current = current.parent
                descriptor = os.open(
                    destination,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                )
                try:
                    with os.fdopen(descriptor, "wb", closefd=False) as stream:
                        stream.write(data)
                        stream.flush()
                        os.fsync(stream.fileno())
                finally:
                    os.close(descriptor)
            output = self._run(
                policy_root,
                (
                    "-c",
                    f"core.excludesFile={os.devnull}",
                    f"--git-dir={location.git_dir}",
                    f"--work-tree={policy_root}",
                    "check-ignore",
                    "-v",
                    "-z",
                    "--no-index",
                    "--stdin",
                ),
                deadline=deadline,
                command_seconds=HARD_LIMITS.git_command_seconds,
                max_output_bytes=_IGNORE_POLICY_OUTPUT_BYTES,
                description="committed audit ignore evaluation",
                input_data=b"".join(
                    path.encode("utf-8", errors="strict") + b"\0" for path in ignored_paths
                ),
                literal_pathspecs=False,
            )

        fields = output.split(b"\0")
        if fields and fields[-1] == b"":
            fields.pop()
        if len(fields) % 4 != 0:
            _error("committed audit ignore evaluation returned ambiguous output")
        matched: dict[str, str] = {}
        try:
            for offset in range(0, len(fields), 4):
                source, _line, _pattern, pathname = (
                    field.decode("utf-8", errors="strict") for field in fields[offset : offset + 4]
                )
                if _pattern.startswith("!"):
                    _error("committed audit ignore policy contains a matching negation")
                if pathname in matched:
                    _error("committed audit ignore evaluation returned duplicate output")
                matched[pathname] = source
        except UnicodeDecodeError as exc:
            raise AuditWorkspaceError(
                "committed audit ignore evaluation returned invalid output"
            ) from exc
        if set(matched) != set(ignored_paths) or any(
            source not in committed for source in matched.values()
        ):
            _error("audit state path is not ignored by committed repository policy")
        self._validate_location_bindings(location)
        return matched

    def _resolve_path(
        self,
        cwd: Path,
        argument: str,
        *,
        deadline: float,
        command_seconds: int,
        description: str,
    ) -> Path:
        output = self._run(
            cwd,
            ("rev-parse", "--path-format=absolute", argument),
            deadline=deadline,
            command_seconds=command_seconds,
            max_output_bytes=_DISCOVERY_OUTPUT_BYTES,
            description=description,
        )
        value = _single_line(output, description)
        path = Path(value)
        if not path.is_absolute():
            _error(f"{description} is not absolute")
        return _absolute_lexical_path(path, description)

    def _resolve_head(
        self,
        cwd: Path,
        *,
        deadline: float,
        command_seconds: int,
    ) -> str:
        output = self._run(
            cwd,
            ("rev-parse", "--verify", "HEAD^{commit}"),
            deadline=deadline,
            command_seconds=command_seconds,
            max_output_bytes=_DISCOVERY_OUTPUT_BYTES,
            description="committed HEAD discovery",
        )
        return _single_oid(output, "committed HEAD")

    def _discover(
        self,
        cwd: Path,
        *,
        deadline: float,
        command_seconds: int,
    ) -> RepositoryLocation:
        _validate_deadline(deadline)
        safe_cwd = _absolute_lexical_path(cwd, "repository discovery directory")
        _capture_safe_directory(safe_cwd, "repository discovery directory")
        root = self._resolve_path(
            safe_cwd,
            "--show-toplevel",
            deadline=deadline,
            command_seconds=command_seconds,
            description="repository root discovery",
        )
        git_dir = self._resolve_path(
            safe_cwd,
            "--absolute-git-dir",
            deadline=deadline,
            command_seconds=command_seconds,
            description="Git directory discovery",
        )
        common_git_dir = self._resolve_path(
            safe_cwd,
            "--git-common-dir",
            deadline=deadline,
            command_seconds=command_seconds,
            description="common Git directory discovery",
        )
        root_identity = _capture_safe_directory(root, "repository root")
        git_dir_identity = _capture_safe_directory(git_dir, "repository Git directory")
        common_git_dir_identity = _capture_safe_directory(
            common_git_dir, "repository common Git directory"
        )
        git_marker_identity = _capture_repository_marker(root)
        _validate_repository_metadata(git_dir, common_git_dir)
        head = self._resolve_head(
            root,
            deadline=deadline,
            command_seconds=command_seconds,
        )
        repository_id = hashlib.sha256(str(root).encode("utf-8", errors="strict")).hexdigest()
        return RepositoryLocation(
            root=root,
            git_dir=git_dir,
            common_git_dir=common_git_dir,
            repository_id=repository_id,
            head=head,
            _root_identity=root_identity,
            _git_marker_identity=git_marker_identity,
            _git_dir_identity=git_dir_identity,
            _common_git_dir_identity=common_git_dir_identity,
        )

    def discover(self, cwd: Path, *, deadline: float) -> RepositoryLocation:
        return self._discover(
            cwd,
            deadline=deadline,
            command_seconds=HARD_LIMITS.git_command_seconds,
        )

    def _revalidate(
        self,
        location: RepositoryLocation,
        *,
        deadline: float,
        command_seconds: int,
    ) -> RepositoryLocation:
        if not isinstance(location, RepositoryLocation):
            _error("repository location is invalid")
        _validate_deadline(deadline)
        self._validate_location_bindings(location)
        self._reject_external_object_sources(
            location,
            deadline=deadline,
            command_seconds=command_seconds,
        )
        current = self._discover(
            location.root,
            deadline=deadline,
            command_seconds=command_seconds,
        )
        if current != location:
            _error("repository binding or committed HEAD changed")
        self._reject_external_object_sources(
            current,
            deadline=deadline,
            command_seconds=command_seconds,
        )
        return current

    def revalidate(
        self,
        location: RepositoryLocation,
        *,
        deadline: float,
    ) -> RepositoryLocation:
        return self._revalidate(
            location,
            deadline=deadline,
            command_seconds=HARD_LIMITS.git_command_seconds,
        )

    def _validate_location_bindings(self, location: RepositoryLocation) -> None:
        _validate_identity(
            location.root,
            location._root_identity,
            "repository root",
        )
        _validate_identity(
            location.git_dir,
            location._git_dir_identity,
            "repository Git directory",
        )
        _validate_identity(
            location.common_git_dir,
            location._common_git_dir_identity,
            "repository common Git directory",
        )
        marker = _capture_repository_marker(location.root)
        if marker != location._git_marker_identity:
            _error("repository Git administration marker binding changed")
        _validate_repository_metadata(location.git_dir, location.common_git_dir)

    def _reject_external_object_sources(
        self,
        location: RepositoryLocation,
        *,
        deadline: float,
        command_seconds: int,
    ) -> None:
        checked: set[Path] = set()
        for git_directory in (location.git_dir, location.common_git_dir):
            if git_directory in checked:
                continue
            checked.add(git_directory)
            for relative_path, description in (
                (Path("objects/info/alternates"), "Git object alternate"),
                (Path("objects/info/http-alternates"), "Git HTTP object alternate"),
                (Path("info/grafts"), "Git graft replacement"),
            ):
                path = git_directory / relative_path
                try:
                    path.lstat()
                except FileNotFoundError:
                    continue
                except OSError as exc:
                    raise AuditWorkspaceError(f"{description} could not be inspected") from exc
                _error(f"{description} is not allowed")
        replacements = self._run(
            location.root,
            ("for-each-ref", "--format=%(refname)", "refs/replace/"),
            deadline=deadline,
            command_seconds=command_seconds,
            max_output_bytes=_DISCOVERY_OUTPUT_BYTES,
            description="Git replacement reference inspection",
        )
        if replacements:
            _error("Git replacement references are not allowed")

    def inspect(
        self,
        location: RepositoryLocation,
        *,
        deadline: float,
    ) -> RepositoryInspection:
        _validate_deadline(deadline)
        self._revalidate(
            location,
            deadline=deadline,
            command_seconds=HARD_LIMITS.git_command_seconds,
        )
        index_data = self._run(
            location.root,
            (
                "ls-files",
                "--stage",
                "--debug",
                "-z",
                "--full-name",
            ),
            deadline=deadline,
            command_seconds=HARD_LIMITS.git_command_seconds,
            max_output_bytes=HARD_LIMITS.git_metadata_bytes,
            description="Git index metadata",
        )
        head_data = self._run(
            location.root,
            (
                "ls-tree",
                "-rz",
                "--full-tree",
                location.head,
            ),
            deadline=deadline,
            command_seconds=HARD_LIMITS.git_command_seconds,
            max_output_bytes=HARD_LIMITS.git_metadata_bytes,
            description="Git HEAD metadata",
        )
        untracked_data = self._run(
            location.root,
            (
                "ls-files",
                "--others",
                "--directory",
                "-z",
                "--full-name",
            ),
            deadline=deadline,
            command_seconds=HARD_LIMITS.git_command_seconds,
            max_output_bytes=HARD_LIMITS.git_metadata_bytes,
            description="Git untracked metadata",
        )
        index_entries = _parse_index_metadata(index_data, HARD_LIMITS)
        head_entries = _parse_head_index_metadata(head_data, HARD_LIMITS)
        stage_zero = {
            entry.path: (entry.mode, entry.object_id) for entry in index_entries if entry.stage == 0
        }
        staged = any(entry.stage != 0 for entry in index_entries) or stage_zero != head_entries
        changes = RepositoryChanges(
            dirty=_tracked_worktree_is_dirty(
                location,
                index_entries,
                deadline=deadline,
            ),
            staged=staged,
            untracked=_parse_untracked_metadata(untracked_data),
        )
        self._validate_location_bindings(location)
        self._reject_external_object_sources(
            location,
            deadline=deadline,
            command_seconds=HARD_LIMITS.git_command_seconds,
        )
        if (
            self._resolve_head(
                location.root,
                deadline=deadline,
                command_seconds=HARD_LIMITS.git_command_seconds,
            )
            != location.head
        ):
            _error("committed HEAD changed during repository inspection")
        return RepositoryInspection(location=location, changes=changes)

    def _tree_entries(
        self,
        inspection: RepositoryInspection,
        *,
        limits: AuditLimits,
        deadline: float,
        command_seconds: int,
    ) -> tuple[tuple[_TreeEntry, ...], int]:
        output = self._run(
            inspection.location.root,
            (
                "ls-tree",
                "-rz",
                "--full-tree",
                "--long",
                inspection.location.head,
            ),
            deadline=deadline,
            command_seconds=command_seconds,
            max_output_bytes=limits.git_metadata_bytes,
            description="Git tree metadata",
        )
        return _parse_tree(output, limits)
