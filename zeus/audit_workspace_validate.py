from __future__ import annotations

import os
import stat
from contextlib import suppress

from zeus.audit_workspace_core import (
    AuditWorkspaceError,
    MaterializedSnapshot,
    _check_optional_deadline,
    _error,
    _path_identity,
    _required_posix_open_flags,
    _validate_deadline,
    _validate_identity,
)
from zeus.audit_workspace_materialize import _AuditWorkspaceMaterialize


class _AuditWorkspaceValidate(_AuditWorkspaceMaterialize):
    def validate_snapshot(
        self,
        snapshot: MaterializedSnapshot,
        *,
        deadline: float | None = None,
    ) -> None:
        if not isinstance(snapshot, MaterializedSnapshot):
            _error("materialized snapshot is invalid")
        validation_deadline = None if deadline is None else _validate_deadline(deadline)
        _check_optional_deadline(validation_deadline)
        _validate_identity(
            snapshot.root,
            snapshot._root_identity,
            "materialized snapshot root",
            private=True,
        )
        _check_optional_deadline(validation_deadline)
        directory_flags = _required_posix_open_flags(
            "O_DIRECTORY",
            "O_NOFOLLOW",
            "O_CLOEXEC",
        )
        try:
            root_descriptor = os.open(snapshot.root, directory_flags)
        except OSError as exc:
            raise AuditWorkspaceError(
                "materialized snapshot root could not be opened safely"
            ) from exc
        try:
            _check_optional_deadline(validation_deadline)
            opened = os.fstat(root_descriptor)
            _check_optional_deadline(validation_deadline)
            if (
                not stat.S_ISDIR(opened.st_mode)
                or _path_identity(opened) != snapshot._root_identity
            ):
                _error("materialized snapshot root binding changed")
            self._validate_snapshot_fd(
                snapshot,
                root_descriptor,
                deadline=validation_deadline,
            )
            _check_optional_deadline(validation_deadline)
            _validate_identity(
                snapshot.root,
                snapshot._root_identity,
                "materialized snapshot root",
                private=True,
            )
            _check_optional_deadline(validation_deadline)
        finally:
            with suppress(OSError):
                os.close(root_descriptor)
