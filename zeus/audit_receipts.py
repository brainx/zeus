from __future__ import annotations

import hashlib
import hmac
import json

from zeus.audit_models import AuditCommandReceipt

_TAG_PREFIX = "hmac-sha256:"
TRUSTED_EXECUTION_BOUNDARY = "isolated-read-only-snapshot-v1"


def _tag(key_hex: str, value: object) -> str:
    key = bytes.fromhex(key_hex)
    canonical = json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return _TAG_PREFIX + hmac.new(key, canonical, hashlib.sha256).hexdigest()


def command_identity_tag(
    *,
    key_hex: str,
    run_id: str,
    target_commit: str,
    snapshot_digest: str,
    image_id: str,
    sequence: int,
    command_script: str,
    isolated_workspace: bool = False,
) -> str:
    """Bind an opaque command identity to the sealed audit execution context."""

    value = {
        "command_sha256": hashlib.sha256(
            command_script.encode("utf-8", errors="strict")
        ).hexdigest(),
        "image_id": image_id,
        "run_id": run_id,
        "schema_version": 2 if isolated_workspace else 1,
        "sequence": sequence,
        "snapshot_digest": snapshot_digest,
        "target_commit": target_commit,
    }
    if isolated_workspace:
        value["execution_boundary"] = TRUSTED_EXECUTION_BOUNDARY
    return _tag(key_hex, value)


def trusted_command_tag(
    *,
    key_hex: str,
    run_id: str,
    target_commit: str,
    snapshot_digest: str,
    image_id: str,
    command_script: str,
) -> str:
    """Return an opaque selector for a configured coverage-bearing command."""

    return _tag(
        key_hex,
        {
            "command_sha256": hashlib.sha256(
                command_script.encode("utf-8", errors="strict")
            ).hexdigest(),
            "image_id": image_id,
            "run_id": run_id,
            "schema_version": 1,
            "snapshot_digest": snapshot_digest,
            "target_commit": target_commit,
            "use": "isolated-command-selector",
        },
    )


def finalize_command_tag(
    *,
    key_hex: str,
    identity_tag: str,
    state: str,
    returncode: int | None,
    duration_ms: int | None,
    stdout_bytes: int | None,
    stderr_bytes: int | None,
) -> str:
    """Bind terminal result metadata without retaining command or output content."""

    return _tag(
        key_hex,
        {
            "duration_ms": duration_ms,
            "identity_tag": identity_tag,
            "returncode": returncode,
            "schema_version": 1,
            "state": state,
            "stderr_bytes": stderr_bytes,
            "stdout_bytes": stdout_bytes,
        },
    )


def expected_command_receipt_tag(
    *,
    key_hex: str,
    run_id: str,
    target_commit: str,
    snapshot_digest: str,
    image_id: str,
    command_script: str,
    receipt: AuditCommandReceipt,
    isolated_workspace: bool = False,
) -> str:
    """Compute the tag a trusted command definition must have for this receipt."""

    identity_tag = command_identity_tag(
        key_hex=key_hex,
        run_id=run_id,
        target_commit=target_commit,
        snapshot_digest=snapshot_digest,
        image_id=image_id,
        sequence=receipt.sequence,
        command_script=command_script,
        isolated_workspace=isolated_workspace,
    )
    if receipt.state == "inflight":
        return identity_tag
    return finalize_command_tag(
        key_hex=key_hex,
        identity_tag=identity_tag,
        state=receipt.state,
        returncode=receipt.returncode,
        duration_ms=receipt.duration_ms,
        stdout_bytes=receipt.stdout_bytes,
        stderr_bytes=receipt.stderr_bytes,
    )
