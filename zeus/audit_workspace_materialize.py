from __future__ import annotations

import hashlib
import os
import stat
import subprocess  # nosec B404
from contextlib import suppress
from pathlib import Path

from zeus.audit_models import AuditLimits, SkippedContent
from zeus.audit_process import AuditProcessError, wait_process_exit
from zeus.audit_workspace_core import (
    _BATCH_HEADER_BYTES,
    _LFS_POINTER_MAX_BYTES,
    _PRIVATE_DIRECTORY_MODE,
    _PRIVATE_EXECUTABLE_MODE,
    _PRIVATE_FILE_MODE,
    _PROCESS_READ_CHUNK,
    _SYMLINK_TARGET_BYTES,
    AuditWorkspaceError,
    MaterializedSnapshot,
    RepositoryInspection,
    RepositoryLocation,
    SnapshotManifestEntry,
    _absolute_lexical_path,
    _blob_size,
    _bounded_deadline,
    _BoundedPipeReader,
    _capture_safe_directory,
    _check_optional_deadline,
    _decode_symlink_target,
    _error,
    _existing_directory_is_within,
    _git_blob_digest,
    _is_excluded,
    _looks_like_lfs_pointer,
    _OpenedSnapshotDestination,
    _path_identity,
    _path_is_within,
    _remaining,
    _required_posix_open_flags,
    _same_identity,
    _stop_process,
    _strict_utf8_path_text,
    _TreeEntry,
    _validate_exclusions,
    _validate_limits,
    _validate_relative_path_text,
    _verify_small_git_blob,
)
from zeus.audit_workspace_git import _AuditWorkspaceGit


class _AuditWorkspaceMaterialize(_AuditWorkspaceGit):
    def _prepare_destination(
        self,
        location: RepositoryLocation,
        destination: Path,
    ) -> _OpenedSnapshotDestination:
        safe_destination = Path(os.path.abspath(destination))
        _strict_utf8_path_text(str(safe_destination), "snapshot destination")
        if safe_destination.name in {"", ".", ".."}:
            _error("snapshot destination must have a confined leaf name")
        for boundary in {
            location.root,
            location.git_dir,
            location.common_git_dir,
        }:
            if _path_is_within(safe_destination, boundary):
                _error("snapshot destination is inside repository boundaries")
        parent = _absolute_lexical_path(safe_destination.parent, "snapshot destination parent")
        for boundary in {
            location.root,
            location.git_dir,
            location.common_git_dir,
        }:
            if _existing_directory_is_within(parent, boundary):
                _error("snapshot destination is inside repository boundaries")
        parent_identity = _capture_safe_directory(
            parent,
            "snapshot destination parent",
            private=True,
        )
        directory_flags = _required_posix_open_flags(
            "O_DIRECTORY",
            "O_NOFOLLOW",
            "O_CLOEXEC",
        )
        try:
            parent_descriptor = os.open(parent, directory_flags)
        except OSError as exc:
            raise AuditWorkspaceError(
                "snapshot destination parent could not be opened safely"
            ) from exc
        except (TypeError, ValueError, NotImplementedError) as exc:
            raise AuditWorkspaceError(
                "snapshot destination parent cannot be opened safely"
            ) from exc
        root_descriptor: int | None = None
        try:
            parent_opened = os.fstat(parent_descriptor)
            try:
                parent_current = _capture_safe_directory(
                    parent,
                    "snapshot destination parent",
                    private=True,
                )
            except AuditWorkspaceError as exc:
                raise AuditWorkspaceError("snapshot destination parent binding changed") from exc
            if (
                _path_identity(parent_opened) != parent_identity
                or parent_current != parent_identity
            ):
                _error("snapshot destination parent binding changed")
            self._validate_location_bindings(location)
            os.mkdir(
                safe_destination.name,
                _PRIVATE_DIRECTORY_MODE,
                dir_fd=parent_descriptor,
            )
        except FileExistsError as exc:
            with suppress(OSError):
                os.close(parent_descriptor)
            raise AuditWorkspaceError("snapshot destination already exists") from exc
        except OSError as exc:
            with suppress(OSError):
                os.close(parent_descriptor)
            raise AuditWorkspaceError("snapshot destination could not be created") from exc
        except (TypeError, ValueError, NotImplementedError) as exc:
            with suppress(OSError):
                os.close(parent_descriptor)
            raise AuditWorkspaceError("snapshot destination cannot be created safely") from exc
        except BaseException:
            with suppress(OSError):
                os.close(parent_descriptor)
            raise
        try:
            before = os.lstat(safe_destination.name, dir_fd=parent_descriptor)
            root_descriptor = os.open(
                safe_destination.name,
                directory_flags,
                dir_fd=parent_descriptor,
            )
            os.fchmod(root_descriptor, _PRIVATE_DIRECTORY_MODE)
            opened = os.fstat(root_descriptor)
            after = os.lstat(safe_destination.name, dir_fd=parent_descriptor)
            before_identity = _path_identity(before)
            root_identity = _path_identity(opened)
            if (
                not stat.S_ISDIR(before.st_mode)
                or not stat.S_ISDIR(opened.st_mode)
                or not stat.S_ISDIR(after.st_mode)
                or before.st_uid != os.geteuid()
                or root_identity.owner != os.geteuid()
                or root_identity.permissions != _PRIVATE_DIRECTORY_MODE
                or not _same_identity(before_identity, root_identity)
                or _path_identity(after) != root_identity
            ):
                _error("snapshot destination binding changed")
            opened_destination = _OpenedSnapshotDestination(
                root=safe_destination,
                parent=parent,
                name=safe_destination.name,
                parent_descriptor=parent_descriptor,
                root_descriptor=root_descriptor,
                parent_identity=parent_identity,
                root_identity=root_identity,
            )
            self._validate_opened_destination(location, opened_destination)
            return opened_destination
        except BaseException:
            if root_descriptor is not None:
                with suppress(OSError):
                    os.fchmod(root_descriptor, _PRIVATE_DIRECTORY_MODE)
                with suppress(OSError):
                    os.close(root_descriptor)
            with suppress(OSError):
                os.close(parent_descriptor)
            raise

    def _validate_opened_destination(
        self,
        location: RepositoryLocation,
        opened_destination: _OpenedSnapshotDestination,
    ) -> None:
        try:
            parent_opened = os.fstat(opened_destination.parent_descriptor)
            root_opened = os.fstat(opened_destination.root_descriptor)
            root_relative = os.lstat(
                opened_destination.name,
                dir_fd=opened_destination.parent_descriptor,
            )
        except OSError as exc:
            raise AuditWorkspaceError("snapshot destination binding changed") from exc
        if _path_identity(parent_opened) != opened_destination.parent_identity:
            _error("snapshot destination parent binding changed")
        try:
            parent_current = _capture_safe_directory(
                opened_destination.parent,
                "snapshot destination parent",
                private=True,
            )
        except AuditWorkspaceError as exc:
            raise AuditWorkspaceError("snapshot destination parent binding changed") from exc
        if parent_current != opened_destination.parent_identity:
            _error("snapshot destination parent binding changed")
        for boundary in {
            location.root,
            location.git_dir,
            location.common_git_dir,
        }:
            if _existing_directory_is_within(opened_destination.parent, boundary):
                _error("snapshot destination is inside repository boundaries")
        self._validate_location_bindings(location)
        root_identity = opened_destination.root_identity
        if (
            not stat.S_ISDIR(root_opened.st_mode)
            or not stat.S_ISDIR(root_relative.st_mode)
            or _path_identity(root_opened) != root_identity
            or _path_identity(root_relative) != root_identity
        ):
            _error("snapshot destination binding changed")
        try:
            root_current = _capture_safe_directory(
                opened_destination.root,
                "snapshot destination",
                private=True,
            )
        except AuditWorkspaceError as exc:
            raise AuditWorkspaceError("snapshot destination binding changed") from exc
        if root_current != root_identity:
            _error("snapshot destination binding changed")
        try:
            parent_final = _capture_safe_directory(
                opened_destination.parent,
                "snapshot destination parent",
                private=True,
            )
        except AuditWorkspaceError as exc:
            raise AuditWorkspaceError("snapshot destination parent binding changed") from exc
        if parent_final != opened_destination.parent_identity:
            _error("snapshot destination parent binding changed")

    def _open_snapshot_subdirectory(
        self,
        parent_descriptor: int,
        component: str,
        *,
        create: bool = True,
    ) -> int:
        created = False
        try:
            before = os.lstat(component, dir_fd=parent_descriptor)
        except FileNotFoundError as exc:
            if not create:
                raise AuditWorkspaceError(
                    "snapshot manifest parent directory is unavailable"
                ) from exc
            try:
                os.mkdir(
                    component,
                    _PRIVATE_DIRECTORY_MODE,
                    dir_fd=parent_descriptor,
                )
                created = True
                before = os.lstat(component, dir_fd=parent_descriptor)
            except FileExistsError as exc:
                raise AuditWorkspaceError(
                    "snapshot parent directory appeared while it was created"
                ) from exc
            except OSError as exc:
                raise AuditWorkspaceError("snapshot parent directory could not be created") from exc
            except (TypeError, ValueError, NotImplementedError) as exc:
                raise AuditWorkspaceError(
                    "snapshot parent directory cannot be created safely"
                ) from exc
        except OSError as exc:
            raise AuditWorkspaceError("snapshot parent directory could not be inspected") from exc
        if (
            not stat.S_ISDIR(before.st_mode)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) & 0o077
        ):
            _error("snapshot parent directory is unsafe")
        directory_flags = _required_posix_open_flags(
            "O_DIRECTORY",
            "O_NOFOLLOW",
            "O_CLOEXEC",
        )
        try:
            descriptor = os.open(
                component,
                directory_flags,
                dir_fd=parent_descriptor,
            )
        except OSError as exc:
            raise AuditWorkspaceError(
                "snapshot parent directory could not be opened safely"
            ) from exc
        except (TypeError, ValueError, NotImplementedError) as exc:
            raise AuditWorkspaceError("snapshot parent directory cannot be opened safely") from exc
        try:
            if created:
                os.fchmod(descriptor, _PRIVATE_DIRECTORY_MODE)
            opened = os.fstat(descriptor)
            after = os.lstat(component, dir_fd=parent_descriptor)
            opened_identity = _path_identity(opened)
            if (
                not stat.S_ISDIR(opened.st_mode)
                or not stat.S_ISDIR(after.st_mode)
                or opened_identity.owner != os.geteuid()
                or opened_identity.permissions != _PRIVATE_DIRECTORY_MODE
                or not _same_identity(_path_identity(before), opened_identity)
                or _path_identity(after) != opened_identity
            ):
                _error("snapshot parent directory binding changed")
            return descriptor
        except AuditWorkspaceError:
            with suppress(OSError):
                os.close(descriptor)
            raise
        except (OSError, TypeError, ValueError, NotImplementedError) as exc:
            with suppress(OSError):
                os.close(descriptor)
            raise AuditWorkspaceError(
                "snapshot parent directory binding could not be validated"
            ) from exc
        except BaseException:
            with suppress(OSError):
                os.close(descriptor)
            raise

    def _prepare_parent_directories(self, root_descriptor: int, path: str) -> int:
        try:
            current_descriptor = os.dup(root_descriptor)
        except OSError as exc:
            raise AuditWorkspaceError("snapshot root descriptor could not be duplicated") from exc
        try:
            for component in path.split("/")[:-1]:
                next_descriptor = self._open_snapshot_subdirectory(
                    current_descriptor,
                    component,
                )
                os.close(current_descriptor)
                current_descriptor = next_descriptor
            return current_descriptor
        except BaseException:
            with suppress(OSError):
                os.close(current_descriptor)
            raise

    def _open_manifest_directory(
        self,
        root_descriptor: int,
        path: str,
    ) -> int:
        try:
            current_descriptor = os.dup(root_descriptor)
        except OSError as exc:
            raise AuditWorkspaceError("snapshot root descriptor could not be duplicated") from exc
        try:
            components = () if not path else tuple(path.split("/"))
            for component in components:
                next_descriptor = self._open_snapshot_subdirectory(
                    current_descriptor,
                    component,
                    create=False,
                )
                os.close(current_descriptor)
                current_descriptor = next_descriptor
            return current_descriptor
        except BaseException:
            with suppress(OSError):
                os.close(current_descriptor)
            raise

    def _open_manifest_parent_directory(
        self,
        root_descriptor: int,
        path: str,
    ) -> int:
        components = path.split("/")
        return self._open_manifest_directory(
            root_descriptor,
            "/".join(components[:-1]),
        )

    def _write_small_regular_file(
        self,
        root_descriptor: int,
        entry: _TreeEntry,
        data: bytes,
    ) -> SnapshotManifestEntry:
        mode = _PRIVATE_EXECUTABLE_MODE if entry.mode == "100755" else _PRIVATE_FILE_MODE
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        for name in ("O_NOFOLLOW", "O_CLOEXEC"):
            value = getattr(os, name, None)
            if not isinstance(value, int) or value == 0:
                _error(f"required POSIX flag {name} is unavailable")
            flags |= value
        parent_descriptor = self._prepare_parent_directories(root_descriptor, entry.path)
        name = entry.path.rsplit("/", 1)[-1]
        try:
            descriptor = os.open(
                name,
                flags,
                mode,
                dir_fd=parent_descriptor,
            )
        except OSError as exc:
            with suppress(OSError):
                os.close(parent_descriptor)
            raise AuditWorkspaceError("materialized snapshot file could not be created") from exc
        except (TypeError, ValueError, NotImplementedError) as exc:
            with suppress(OSError):
                os.close(parent_descriptor)
            raise AuditWorkspaceError(
                "materialized snapshot file cannot be created safely"
            ) from exc
        try:
            os.fchmod(descriptor, mode)
            view = memoryview(data)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    _error("materialized snapshot file write made no progress")
                view = view[written:]
        except OSError as exc:
            raise AuditWorkspaceError("materialized snapshot file could not be written") from exc
        finally:
            with suppress(OSError):
                os.close(descriptor)
            with suppress(OSError):
                os.close(parent_descriptor)
        return SnapshotManifestEntry(
            path=entry.path,
            object_id=entry.object_id,
            git_mode=entry.mode,
            mode=mode,
            size=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
        )

    def _write_streamed_regular_file(
        self,
        root_descriptor: int,
        entry: _TreeEntry,
        reader: _BoundedPipeReader,
    ) -> SnapshotManifestEntry:
        entry_size = _blob_size(entry)
        mode = _PRIVATE_EXECUTABLE_MODE if entry.mode == "100755" else _PRIVATE_FILE_MODE
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        for name in ("O_NOFOLLOW", "O_CLOEXEC"):
            value = getattr(os, name, None)
            if not isinstance(value, int) or value == 0:
                _error(f"required POSIX flag {name} is unavailable")
            flags |= value
        parent_descriptor = self._prepare_parent_directories(root_descriptor, entry.path)
        name = entry.path.rsplit("/", 1)[-1]
        try:
            descriptor = os.open(
                name,
                flags,
                mode,
                dir_fd=parent_descriptor,
            )
        except OSError as exc:
            with suppress(OSError):
                os.close(parent_descriptor)
            raise AuditWorkspaceError("materialized snapshot file could not be created") from exc
        except (TypeError, ValueError, NotImplementedError) as exc:
            with suppress(OSError):
                os.close(parent_descriptor)
            raise AuditWorkspaceError(
                "materialized snapshot file cannot be created safely"
            ) from exc
        digest = hashlib.sha256()
        git_digest = _git_blob_digest(entry.object_id, entry_size)
        try:
            os.fchmod(descriptor, mode)
            reader.copy_exact(entry_size, descriptor, (digest, git_digest))
        except OSError as exc:
            raise AuditWorkspaceError("materialized snapshot file could not be written") from exc
        finally:
            with suppress(OSError):
                os.close(descriptor)
            with suppress(OSError):
                os.close(parent_descriptor)
        if git_digest.hexdigest() != entry.object_id:
            _error("Git blob content does not match its object ID")
        return SnapshotManifestEntry(
            path=entry.path,
            object_id=entry.object_id,
            git_mode=entry.mode,
            mode=mode,
            size=entry_size,
            sha256=digest.hexdigest(),
        )

    def _write_symlink(
        self,
        root_descriptor: int,
        entry: _TreeEntry,
        data: bytes,
    ) -> SnapshotManifestEntry:
        target = _decode_symlink_target(data, entry.path)
        parent_descriptor = self._prepare_parent_directories(root_descriptor, entry.path)
        name = entry.path.rsplit("/", 1)[-1]
        try:
            os.symlink(target, name, dir_fd=parent_descriptor)
        except OSError as exc:
            raise AuditWorkspaceError("materialized snapshot symlink could not be created") from exc
        except (TypeError, ValueError, NotImplementedError) as exc:
            raise AuditWorkspaceError(
                "materialized snapshot symlink cannot be created safely"
            ) from exc
        finally:
            with suppress(OSError):
                os.close(parent_descriptor)
        return SnapshotManifestEntry(
            path=entry.path,
            object_id=entry.object_id,
            git_mode=entry.mode,
            mode=0o777,
            size=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
            symlink_target=target,
        )

    def _read_batch_header(self, reader: _BoundedPipeReader, entry: _TreeEntry) -> None:
        line = reader.read_until(b"\n", _BATCH_HEADER_BYTES)
        try:
            object_id_bytes, object_type, size_bytes = line[:-1].split()
            object_id = object_id_bytes.decode("ascii", errors="strict")
            size = int(size_bytes.decode("ascii", errors="strict"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise AuditWorkspaceError("Git blob stream returned an invalid header") from exc
        if (
            object_id != entry.object_id
            or object_type != b"blob"
            or entry.size is None
            or size != entry.size
        ):
            _error("Git blob stream returned an unexpected object")

    def _materialize_blobs(
        self,
        location: RepositoryLocation,
        entries: tuple[_TreeEntry, ...],
        root_descriptor: int,
        exclusions: tuple[str, ...],
        limits: AuditLimits,
        deadline: float,
    ) -> tuple[tuple[SnapshotManifestEntry, ...], tuple[SkippedContent, ...]]:
        command_deadline = _bounded_deadline(deadline, limits.git_command_seconds)
        manifest: list[SnapshotManifestEntry] = []
        skipped = [
            SkippedContent(path=entry.path, reason="gitlink")
            for entry in entries
            if entry.mode == "160000"
        ]
        skipped.extend(
            SkippedContent(path=path, reason="excluded by audit configuration")
            for path in exclusions
        )
        process = self._spawn(
            location.root,
            ("cat-file", "--batch"),
            stdin=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        if process.stdin is None or process.stdout is None:
            _stop_process(process)
            _error("Git blob process pipes are unavailable")
        requested = tuple(
            entry
            for entry in entries
            if entry.mode != "160000" and not _is_excluded(entry.path, exclusions)
        )
        header_allowance = min(
            limits.git_metadata_bytes,
            max(1, len(requested)) * _BATCH_HEADER_BYTES,
        )
        reader = _BoundedPipeReader(
            process.stdout,
            deadline=command_deadline,
            byte_limit=limits.snapshot_blob_bytes + header_allowance + len(requested),
        )
        try:
            for entry in requested:
                _remaining(command_deadline)
                try:
                    process.stdin.write(f"{entry.object_id}\n".encode("ascii"))
                    process.stdin.flush()
                except (BrokenPipeError, OSError) as exc:
                    raise AuditWorkspaceError("Git blob request could not be written") from exc
                self._read_batch_header(reader, entry)
                entry_size = _blob_size(entry)
                if entry.mode == "120000":
                    if entry_size > _SYMLINK_TARGET_BYTES:
                        _error(f"snapshot symlink target for {entry.path} is too large")
                    data = reader.read_exact(entry_size)
                    if reader.read_exact(1) != b"\n":
                        _error("Git blob stream returned an invalid object terminator")
                    _verify_small_git_blob(entry, data)
                    manifest.append(self._write_symlink(root_descriptor, entry, data))
                    continue
                if entry_size < _LFS_POINTER_MAX_BYTES:
                    data = reader.read_exact(entry_size)
                    if reader.read_exact(1) != b"\n":
                        _error("Git blob stream returned an invalid object terminator")
                    _verify_small_git_blob(entry, data)
                    if _looks_like_lfs_pointer(data):
                        skipped.append(SkippedContent(path=entry.path, reason="git-lfs-pointer"))
                        continue
                    manifest.append(self._write_small_regular_file(root_descriptor, entry, data))
                    continue
                manifest.append(self._write_streamed_regular_file(root_descriptor, entry, reader))
                if reader.read_exact(1) != b"\n":
                    _error("Git blob stream returned an invalid object terminator")
            try:
                process.stdin.close()
                reader.ensure_eof()
                return_code = wait_process_exit(process, deadline=command_deadline)
            except (AuditProcessError, subprocess.TimeoutExpired):
                _stop_process(process)
                _error("Git blob stream exceeded its deadline")
            if return_code != 0:
                _error("Git blob stream failed")
            return tuple(manifest), tuple(sorted(skipped, key=lambda item: item.path))
        finally:
            reader.close()
            with suppress(OSError):
                process.stdin.close()
            with suppress(OSError):
                process.stdout.close()
            if process.returncode is None:
                _stop_process(process)

    def _cleanup_opened_snapshot(
        self,
        opened_destination: _OpenedSnapshotDestination,
    ) -> None:
        try:
            root_opened = os.fstat(opened_destination.root_descriptor)
        except OSError:
            return
        if (
            not stat.S_ISDIR(root_opened.st_mode)
            or root_opened.st_uid != os.geteuid()
            or not _same_identity(
                _path_identity(root_opened),
                opened_destination.root_identity,
            )
        ):
            return
        with suppress(OSError):
            os.fchmod(
                opened_destination.root_descriptor,
                _PRIVATE_DIRECTORY_MODE,
            )

    def materialize(
        self,
        inspection: RepositoryInspection,
        destination: Path,
        *,
        exclude_paths: tuple[str, ...],
        limits: AuditLimits,
        deadline: float,
    ) -> MaterializedSnapshot:
        if not isinstance(inspection, RepositoryInspection):
            _error("repository inspection is invalid")
        if not isinstance(destination, Path):
            _error("snapshot destination must be a pathlib.Path")
        _validate_limits(limits)
        exclusions = _validate_exclusions(exclude_paths)
        materialization_deadline = _bounded_deadline(deadline, limits.materialization_seconds)
        location = inspection.location
        self._revalidate(
            location,
            deadline=materialization_deadline,
            command_seconds=limits.git_command_seconds,
        )
        entries, blob_bytes = self._tree_entries(
            inspection,
            limits=limits,
            deadline=materialization_deadline,
            command_seconds=limits.git_command_seconds,
        )
        self._validate_location_bindings(location)
        if (
            self._resolve_head(
                location.root,
                deadline=materialization_deadline,
                command_seconds=limits.git_command_seconds,
            )
            != location.head
        ):
            _error("committed HEAD changed during tree enumeration")

        opened_destination = self._prepare_destination(location, destination)
        try:
            manifest, skipped = self._materialize_blobs(
                location,
                entries,
                opened_destination.root_descriptor,
                exclusions,
                limits,
                materialization_deadline,
            )
            self._validate_opened_destination(location, opened_destination)
            self._validate_location_bindings(location)
            self._reject_external_object_sources(
                location,
                deadline=materialization_deadline,
                command_seconds=limits.git_command_seconds,
            )
            final_head = self._resolve_head(
                location.root,
                deadline=materialization_deadline,
                command_seconds=limits.git_command_seconds,
            )
            if final_head != location.head:
                _error("committed HEAD changed during snapshot materialization")
            snapshot = MaterializedSnapshot(
                root=opened_destination.root,
                repository_id=location.repository_id,
                head=location.head,
                manifest=manifest,
                skipped_content=skipped,
                source_entry_count=len(entries),
                source_blob_bytes=blob_bytes,
                excluded_paths=exclusions,
                _root_identity=opened_destination.root_identity,
            )
            self._validate_snapshot_fd(
                snapshot,
                opened_destination.root_descriptor,
                deadline=materialization_deadline,
            )
            self._validate_opened_destination(location, opened_destination)
            return snapshot
        except BaseException:
            self._cleanup_opened_snapshot(opened_destination)
            raise
        finally:
            with suppress(OSError):
                os.close(opened_destination.root_descriptor)
            with suppress(OSError):
                os.close(opened_destination.parent_descriptor)

    def _hash_regular_file_at(
        self,
        parent_descriptor: int,
        name: str,
        expected: os.stat_result,
        *,
        deadline: float | None = None,
    ) -> str:
        _check_optional_deadline(deadline)
        flags = _required_posix_open_flags("O_NOFOLLOW", "O_CLOEXEC")
        try:
            descriptor = os.open(
                name,
                flags,
                dir_fd=parent_descriptor,
            )
        except OSError as exc:
            raise AuditWorkspaceError("snapshot manifest file could not be opened") from exc
        except (TypeError, ValueError, NotImplementedError) as exc:
            raise AuditWorkspaceError("snapshot manifest file cannot be opened safely") from exc
        digest = hashlib.sha256()
        try:
            _check_optional_deadline(deadline)
            opened = os.fstat(descriptor)
            _check_optional_deadline(deadline)
            if (
                opened.st_dev != expected.st_dev
                or opened.st_ino != expected.st_ino
                or opened.st_size != expected.st_size
            ):
                _error("snapshot manifest file binding changed")
            while True:
                _check_optional_deadline(deadline)
                chunk = os.read(descriptor, _PROCESS_READ_CHUNK)
                _check_optional_deadline(deadline)
                if not chunk:
                    break
                digest.update(chunk)
        except OSError as exc:
            raise AuditWorkspaceError("snapshot manifest file could not be read") from exc
        finally:
            with suppress(OSError):
                os.close(descriptor)
        try:
            _check_optional_deadline(deadline)
            current = os.lstat(name, dir_fd=parent_descriptor)
            _check_optional_deadline(deadline)
        except OSError as exc:
            raise AuditWorkspaceError("snapshot manifest file binding changed") from exc
        if (
            current.st_dev != expected.st_dev
            or current.st_ino != expected.st_ino
            or current.st_size != expected.st_size
            or stat.S_IMODE(current.st_mode) != stat.S_IMODE(expected.st_mode)
        ):
            _error("snapshot manifest file binding changed")
        return digest.hexdigest()

    def _validate_snapshot_fd(
        self,
        snapshot: MaterializedSnapshot,
        root_descriptor: int,
        *,
        deadline: float | None = None,
    ) -> None:
        _check_optional_deadline(deadline)
        try:
            root_opened = os.fstat(root_descriptor)
        except OSError as exc:
            raise AuditWorkspaceError("materialized snapshot root could not be inspected") from exc
        _check_optional_deadline(deadline)
        if (
            not stat.S_ISDIR(root_opened.st_mode)
            or _path_identity(root_opened) != snapshot._root_identity
        ):
            _error("materialized snapshot root binding changed")

        expected_entries: dict[str, SnapshotManifestEntry] = {}
        expected_directories: set[str] = set()
        for entry in snapshot.manifest:
            _check_optional_deadline(deadline)
            if not isinstance(entry, SnapshotManifestEntry):
                _error("snapshot manifest contains an invalid entry")
            path = _validate_relative_path_text(entry.path, "snapshot manifest path")
            if path in expected_entries:
                _error("snapshot manifest contains a duplicate path")
            expected_entries[path] = entry
            components = path.split("/")
            expected_directories.update(
                "/".join(components[:index]) for index in range(1, len(components))
            )
            _check_optional_deadline(deadline)

        actual_paths: set[str] = set()
        pending = [""]
        while pending:
            _check_optional_deadline(deadline)
            relative_directory = pending.pop()
            directory_descriptor = self._open_manifest_directory(
                root_descriptor,
                relative_directory,
            )
            try:
                _check_optional_deadline(deadline)
                directory_result = os.fstat(directory_descriptor)
                _check_optional_deadline(deadline)
                try:
                    with os.scandir(directory_descriptor) as iterator:
                        children = list(iterator)
                    _check_optional_deadline(deadline)
                except OSError as exc:
                    raise AuditWorkspaceError(
                        "snapshot manifest directory could not be read"
                    ) from exc
                if relative_directory:
                    if (
                        not stat.S_ISDIR(directory_result.st_mode)
                        or directory_result.st_uid != os.geteuid()
                        or stat.S_IMODE(directory_result.st_mode) != _PRIVATE_DIRECTORY_MODE
                    ):
                        _error("snapshot manifest directory validation failed")
                    actual_paths.add(relative_directory)
                elif _path_identity(directory_result) != snapshot._root_identity:
                    _error("materialized snapshot root binding changed")
                for child in children:
                    _check_optional_deadline(deadline)
                    relative = (
                        child.name
                        if not relative_directory
                        else f"{relative_directory}/{child.name}"
                    )
                    _validate_relative_path_text(relative, "snapshot manifest path")
                    try:
                        result = child.stat(follow_symlinks=False)
                    except OSError as exc:
                        raise AuditWorkspaceError(
                            "snapshot manifest entry could not be inspected"
                        ) from exc
                    _check_optional_deadline(deadline)
                    actual_paths.add(relative)
                    if stat.S_ISDIR(result.st_mode):
                        pending.append(relative)
            finally:
                with suppress(OSError):
                    os.close(directory_descriptor)

        _check_optional_deadline(deadline)
        expected_paths = set(expected_entries) | expected_directories
        if actual_paths != expected_paths:
            _error("snapshot manifest paths do not match materialized content")

        for path, entry in expected_entries.items():
            _check_optional_deadline(deadline)
            parent_descriptor = self._open_manifest_parent_directory(
                root_descriptor,
                path,
            )
            name = path.rsplit("/", 1)[-1]
            try:
                try:
                    result = os.lstat(name, dir_fd=parent_descriptor)
                except OSError as exc:
                    raise AuditWorkspaceError("snapshot manifest entry is unavailable") from exc
                _check_optional_deadline(deadline)
                if result.st_uid != os.geteuid():
                    _error("snapshot manifest entry has an unexpected owner")
                if entry.is_symlink:
                    if not stat.S_ISLNK(result.st_mode):
                        _error("snapshot manifest symlink type does not match")
                    try:
                        _check_optional_deadline(deadline)
                        target = os.readlink(name, dir_fd=parent_descriptor)
                        _check_optional_deadline(deadline)
                    except OSError as exc:
                        raise AuditWorkspaceError(
                            "snapshot manifest symlink could not be read"
                        ) from exc
                    if target != entry.symlink_target:
                        _error("snapshot manifest symlink target does not match")
                    _decode_symlink_target(target.encode("utf-8"), path)
                    try:
                        _check_optional_deadline(deadline)
                        current = os.lstat(name, dir_fd=parent_descriptor)
                        _check_optional_deadline(deadline)
                    except OSError as exc:
                        raise AuditWorkspaceError(
                            "snapshot manifest symlink binding changed"
                        ) from exc
                    if (
                        current.st_dev != result.st_dev
                        or current.st_ino != result.st_ino
                        or not stat.S_ISLNK(current.st_mode)
                    ):
                        _error("snapshot manifest symlink binding changed")
                    if (
                        entry.size != len(target.encode("utf-8"))
                        or hashlib.sha256(target.encode("utf-8")).hexdigest() != entry.sha256
                    ):
                        _error("snapshot manifest symlink digest does not match")
                    continue
                if (
                    not stat.S_ISREG(result.st_mode)
                    or result.st_nlink != 1
                    or stat.S_IMODE(result.st_mode) != entry.mode
                    or result.st_size != entry.size
                ):
                    _error("snapshot manifest regular file metadata does not match")
                if (
                    self._hash_regular_file_at(
                        parent_descriptor,
                        name,
                        result,
                        deadline=deadline,
                    )
                    != entry.sha256
                ):
                    _error("snapshot manifest regular file digest does not match")
                _check_optional_deadline(deadline)
            finally:
                with suppress(OSError):
                    os.close(parent_descriptor)

        _check_optional_deadline(deadline)
        try:
            root_final = os.fstat(root_descriptor)
        except OSError as exc:
            raise AuditWorkspaceError("materialized snapshot root could not be inspected") from exc
        _check_optional_deadline(deadline)
        if (
            not stat.S_ISDIR(root_final.st_mode)
            or _path_identity(root_final) != snapshot._root_identity
        ):
            _error("materialized snapshot root binding changed")
