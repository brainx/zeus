"""Constant source for attesting the trusted read-only audit snapshot."""

from __future__ import annotations

TRUSTED_EXEC_ENV = (
    "HOME=/tmp",
    "TMPDIR=/tmp",
    "XDG_CACHE_HOME=/tmp/.cache",
    "XDG_CONFIG_HOME=/tmp/.config",
    "XDG_DATA_HOME=/tmp/.local/share",
    "XDG_STATE_HOME=/tmp/.local/state",
    "PYTHONDONTWRITEBYTECODE=1",
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG=C",
    "LC_ALL=C",
    "TZ=UTC",
)
TRUSTED_EXEC_PREFIX = ("/usr/bin/env", "-i", *TRUSTED_EXEC_ENV)

ATTEST_SCRIPT = r"""
import hashlib, json, os, stat, sys
if len(sys.argv) != 5 or len(sys.argv[1]) != 64:
    raise RuntimeError("trusted snapshot attestation arguments are invalid")
expected_digest = sys.argv[1]
expected_uid = int(sys.argv[2])
expected_gid = int(sys.argv[3])
expected_temp_bytes = int(sys.argv[4])
if expected_uid <= 0 or expected_gid < 0 or expected_temp_bytes <= 0:
    raise RuntimeError("trusted snapshot attestation identity is invalid")
if os.getuid() != expected_uid or os.getgid() != expected_gid:
    raise RuntimeError("trusted snapshot process identity mismatch")
if os.getgroups() != [expected_gid]:
    raise RuntimeError("trusted snapshot supplementary groups mismatch")
workspace_root = os.stat("/workspace", follow_symlinks=False)
if (
    not stat.S_ISDIR(workspace_root.st_mode)
    or stat.S_IMODE(workspace_root.st_mode) != 0o700
    or workspace_root.st_uid != expected_uid
    or workspace_root.st_gid != expected_gid
):
    raise RuntimeError("trusted snapshot root metadata mismatch")
with open("/proc/self/status", encoding="ascii") as source:
    process_status = dict(
        line.rstrip("\n").split(":\t", 1)
        for line in source
        if ":\t" in line
    )
if (
    process_status.get("NoNewPrivs") != "1"
    or process_status.get("Seccomp") != "2"
    or int(process_status.get("CapEff", "-1"), 16) != 0
):
    raise RuntimeError("trusted snapshot process isolation mismatch")
mount_records = {}
with open("/proc/self/mountinfo", encoding="ascii") as source:
    for raw_line in source:
        if not raw_line.endswith("\n"):
            raise RuntimeError("trusted snapshot mount information is malformed")
        fields = raw_line[:-1].split(" ")
        separators = [index for index, value in enumerate(fields) if value == "-"]
        if (
            len(fields) < 10
            or any(not field for field in fields)
            or len(separators) != 1
            or separators[0] < 6
            or separators[0] + 4 != len(fields)
        ):
            raise RuntimeError("trusted snapshot mount information is malformed")
        if fields[4] in {"/", "/workspace", "/tmp"}:
            if fields[4] in mount_records:
                raise RuntimeError("trusted snapshot mount information is ambiguous")
            mount_records[fields[4]] = (fields, separators[0])
if set(mount_records) != {"/", "/workspace", "/tmp"}:
    raise RuntimeError("trusted snapshot effective mounts are missing")
root_fields, root_separator = mount_records["/"]
root_options = set(root_fields[5].split(","))
if "ro" not in root_options or "rw" in root_options:
    raise RuntimeError("trusted snapshot root filesystem is not read-only")
workspace_fields, workspace_separator = mount_records["/workspace"]
workspace_options = set(workspace_fields[5].split(","))
workspace_device = f"{os.major(workspace_root.st_dev)}:{os.minor(workspace_root.st_dev)}"
if (
    workspace_fields[2] != workspace_device
    or "ro" not in workspace_options
    or "rw" in workspace_options
):
    raise RuntimeError("trusted snapshot workspace is not read-only")
temp_fields, temp_separator = mount_records["/tmp"]
temp_options = set(temp_fields[5].split(","))
temp_super_options = set(temp_fields[temp_separator + 3].split(","))
temp_root = os.stat("/tmp", follow_symlinks=False)
temp_stats = os.statvfs("/tmp")
temp_device = f"{os.major(temp_root.st_dev)}:{os.minor(temp_root.st_dev)}"
if (
    not stat.S_ISDIR(temp_root.st_mode)
    or stat.S_IMODE(temp_root.st_mode) != 0o700
    or temp_root.st_uid != expected_uid
    or temp_root.st_gid != expected_gid
    or temp_fields[2] != temp_device
    or temp_fields[3] != "/"
    or temp_fields[temp_separator + 1] != "tmpfs"
    or temp_fields[temp_separator + 2] != "tmpfs"
    or not {"rw", "noexec", "nosuid", "nodev"}.issubset(temp_options)
    or "ro" in temp_options
    or "rw" not in temp_super_options
    or temp_stats.f_blocks * temp_stats.f_frsize != expected_temp_bytes
):
    raise RuntimeError("trusted snapshot temporary mount policy mismatch")
entries = []
actual_directories = set()
entry_count = 0
blob_bytes = 0
pending = [("", os.open("/workspace", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW))]
try:
    while pending:
        prefix, directory = pending.pop()
        try:
            for name in sorted(os.listdir(directory)):
                path = name if not prefix else prefix + "/" + name
                item = os.stat(name, dir_fd=directory, follow_symlinks=False)
                if stat.S_ISDIR(item.st_mode):
                    if (
                        stat.S_IMODE(item.st_mode) != 0o700
                        or item.st_uid != expected_uid
                        or item.st_gid != expected_gid
                    ):
                        raise RuntimeError("trusted snapshot directory metadata is invalid")
                    actual_directories.add(path)
                    child = os.open(
                        name,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=directory,
                    )
                    pending.append((path, child))
                    continue
                entry_count += 1
                if entry_count > 100000:
                    raise RuntimeError("trusted snapshot entry limit exceeded")
                if stat.S_ISLNK(item.st_mode):
                    if item.st_uid != expected_uid or item.st_gid != expected_gid:
                        raise RuntimeError("trusted snapshot symlink ownership is invalid")
                    target = os.readlink(name, dir_fd=directory)
                    encoded_target = target.encode("utf-8", errors="strict")
                    blob_bytes += len(encoded_target)
                    entries.append(
                        {
                            "git_mode": "120000",
                            "mode": 0o777,
                            "path": path,
                            "sha256": hashlib.sha256(encoded_target).hexdigest(),
                            "size": len(encoded_target),
                            "symlink_target": target,
                        }
                    )
                    continue
                if not stat.S_ISREG(item.st_mode) or item.st_nlink != 1:
                    raise RuntimeError("trusted snapshot entry type is invalid")
                mode = stat.S_IMODE(item.st_mode)
                if mode not in {0o600, 0o700}:
                    raise RuntimeError("trusted snapshot file mode is invalid")
                if item.st_uid != expected_uid or item.st_gid != expected_gid:
                    raise RuntimeError("trusted snapshot file ownership is invalid")
                blob_bytes += item.st_size
                if blob_bytes > 1073741824:
                    raise RuntimeError("trusted snapshot byte limit exceeded")
                opened = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
                try:
                    opened_item = os.fstat(opened)
                    if (
                        opened_item.st_dev != item.st_dev
                        or opened_item.st_ino != item.st_ino
                        or opened_item.st_size != item.st_size
                        or stat.S_IMODE(opened_item.st_mode) != mode
                        or opened_item.st_nlink != 1
                    ):
                        raise RuntimeError("trusted snapshot file binding changed")
                    digest = hashlib.sha256()
                    while True:
                        chunk = os.read(opened, 65536)
                        if not chunk:
                            break
                        digest.update(chunk)
                    final_opened_item = os.fstat(opened)
                finally:
                    os.close(opened)
                final_item = os.stat(name, dir_fd=directory, follow_symlinks=False)
                if (
                    final_opened_item.st_dev != item.st_dev
                    or final_opened_item.st_ino != item.st_ino
                    or final_opened_item.st_size != item.st_size
                    or final_item.st_dev != item.st_dev
                    or final_item.st_ino != item.st_ino
                    or final_item.st_size != item.st_size
                    or stat.S_IMODE(final_item.st_mode) != mode
                    or final_item.st_nlink != 1
                ):
                    raise RuntimeError("trusted snapshot file changed during attestation")
                entries.append(
                    {
                        "git_mode": "100755" if mode == 0o700 else "100644",
                        "mode": mode,
                        "path": path,
                        "sha256": digest.hexdigest(),
                        "size": item.st_size,
                        "symlink_target": None,
                    }
                )
        finally:
            os.close(directory)
finally:
    while pending:
        os.close(pending.pop()[1])
surface = hashlib.sha256()
surface.update(b"[")
for index, entry in enumerate(sorted(entries, key=lambda value: value["path"])):
    if index:
        surface.update(b",")
    surface.update(
        json.dumps(
            entry,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    )
surface.update(b"]")
expected_directories = set()
for entry in entries:
    parts = entry["path"].split("/")
    expected_directories.update("/".join(parts[:index]) for index in range(1, len(parts)))
if actual_directories != expected_directories:
    raise RuntimeError("trusted snapshot directory set mismatch")
if surface.hexdigest() != expected_digest:
    raise RuntimeError("trusted snapshot digest mismatch")
""".strip()
