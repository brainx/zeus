"""Constant source for the isolated audit workspace validation process."""

from __future__ import annotations

VALIDATION_SCRIPT = r"""
import hashlib, json, os, stat, sys
if len(sys.argv) != 13:
    raise RuntimeError("workspace validation arguments are invalid")
expected_uid = int(sys.argv[1])
expected_gid = int(sys.argv[2])
expected_entry_uid = int(sys.argv[3])
expected_entry_gid = int(sys.argv[4])
expected_groups = json.loads(sys.argv[5])
status_path = sys.argv[6]
mountinfo_path = sys.argv[7]
probe_root = sys.argv[8]
workspace_path = os.path.abspath(sys.argv[9])
temp_path = os.path.abspath(sys.argv[10])
expected_workspace_bytes = int(sys.argv[11])
expected_temp_bytes = int(sys.argv[12])
if (
    not isinstance(expected_groups, list)
    or any(
        isinstance(group, bool) or not isinstance(group, int)
        for group in expected_groups
    )
):
    raise RuntimeError("workspace validation supplementary groups are invalid")
if expected_workspace_bytes < 1 or expected_temp_bytes < 1 or workspace_path == temp_path:
    raise RuntimeError("workspace validation mount arguments are invalid")
if os.getuid() != expected_uid or os.getgid() != expected_gid:
    raise RuntimeError("workspace validation process identity mismatch")
if os.getgroups() != expected_groups:
    raise RuntimeError("workspace validation supplementary groups mismatch")
expected = {item["path"]: item for item in json.load(sys.stdin)}
expected_dirs = set()
for path in expected:
    parts = path.split("/")
    expected_dirs.update("/".join(parts[:i]) for i in range(1, len(parts)))
actual = set()
root = os.stat(".", follow_symlinks=False)
if (
    not stat.S_ISDIR(root.st_mode)
    or stat.S_IMODE(root.st_mode) != 0o700
    or root.st_uid != expected_entry_uid
    or root.st_gid != expected_entry_gid
):
    raise RuntimeError("workspace root metadata mismatch")
with open(status_path, encoding="ascii") as source:
    process_status = dict(
        line.rstrip("\n").split(":\t", 1)
        for line in source
        if ":\t" in line
    )
if process_status.get("NoNewPrivs") != "1":
    raise RuntimeError("no-new-privileges is not effective")
if process_status.get("Seccomp") != "2":
    raise RuntimeError("the Docker seccomp filter is not effective")
if int(process_status.get("CapEff", "-1"), 16) != 0:
    raise RuntimeError("effective Linux capabilities were not fully dropped")
expected_mount_paths = {workspace_path, temp_path}
mount_records = {}
with open(mountinfo_path, encoding="ascii") as source:
    for raw_line in source:
        if not raw_line.endswith("\n"):
            raise RuntimeError("effective mount information is malformed")
        fields = raw_line[:-1].split(" ")
        separators = [index for index, value in enumerate(fields) if value == "-"]
        if (
            len(fields) < 10
            or any(not field for field in fields)
            or len(separators) != 1
            or separators[0] < 6
            or separators[0] + 4 != len(fields)
        ):
            raise RuntimeError("effective mount information is malformed")
        mount_path = fields[4]
        if mount_path in expected_mount_paths:
            if mount_path in mount_records:
                raise RuntimeError("effective mount information is ambiguous")
            mount_records[mount_path] = (fields, separators[0])
if set(mount_records) != expected_mount_paths:
    raise RuntimeError("required effective mount is missing")


def validate_mount(path, expected_bytes, require_noexec):
    flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = os.open(path, flags)
    try:
        item = os.fstat(descriptor)
        filesystem = os.fstatvfs(descriptor)
    finally:
        os.close(descriptor)
    if (
        not stat.S_ISDIR(item.st_mode)
        or stat.S_IMODE(item.st_mode) != 0o700
        or item.st_uid != expected_entry_uid
        or item.st_gid != expected_entry_gid
    ):
        raise RuntimeError("effective mount metadata mismatch")
    if filesystem.f_blocks * filesystem.f_frsize != expected_bytes:
        raise RuntimeError("effective mount capacity mismatch")
    fields, separator = mount_records[path]
    device = f"{os.major(item.st_dev)}:{os.minor(item.st_dev)}"
    mount_options = set(fields[5].split(","))
    super_options = set(fields[separator + 3].split(","))
    if (
        fields[2] != device
        or fields[3] != "/"
        or fields[separator + 1] != "tmpfs"
        or fields[separator + 2] != "tmpfs"
        or not {"rw", "nosuid", "nodev"}.issubset(mount_options)
        or "ro" in mount_options
        or ("noexec" in mount_options) != require_noexec
        or "rw" not in super_options
        or "ro" in super_options
    ):
        raise RuntimeError("effective mount policy mismatch")


validate_mount(workspace_path, expected_workspace_bytes, False)
validate_mount(temp_path, expected_temp_bytes, True)
pending = [("", os.open(".", os.O_RDONLY | os.O_DIRECTORY))]
try:
    while pending:
        prefix, descriptor = pending.pop()
        try:
            for name in os.listdir(descriptor):
                path = name if not prefix else prefix + "/" + name
                item = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                actual.add(path)
                if stat.S_ISDIR(item.st_mode):
                    if path in expected:
                        raise RuntimeError("workspace entry type mismatch")
                    if (
                        stat.S_IMODE(item.st_mode) != 0o700
                        or item.st_uid != expected_entry_uid
                        or item.st_gid != expected_entry_gid
                    ):
                        raise RuntimeError("workspace directory metadata mismatch")
                    child = os.open(
                        name,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=descriptor,
                    )
                    pending.append((path, child))
                    continue
                wanted = expected.get(path)
                if wanted is None:
                    raise RuntimeError("unexpected workspace entry")
                if item.st_uid != expected_entry_uid or item.st_gid != expected_entry_gid:
                    raise RuntimeError("workspace entry ownership mismatch")
                if wanted["type"] == "symlink":
                    if not stat.S_ISLNK(item.st_mode):
                        raise RuntimeError("workspace entry type mismatch")
                    if os.readlink(name, dir_fd=descriptor) != wanted["target"]:
                        raise RuntimeError("workspace symlink target mismatch")
                    continue
                if not stat.S_ISREG(item.st_mode):
                    raise RuntimeError("workspace entry type mismatch")
                if stat.S_IMODE(item.st_mode) != wanted["mode"] or item.st_size != wanted["size"]:
                    raise RuntimeError("workspace file metadata mismatch")
                opened = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptor)
                try:
                    digest = hashlib.sha256()
                    while True:
                        chunk = os.read(opened, 65536)
                        if not chunk:
                            break
                        digest.update(chunk)
                finally:
                    os.close(opened)
                if digest.hexdigest() != wanted["sha256"]:
                    raise RuntimeError("workspace file digest mismatch")
        finally:
            os.close(descriptor)
finally:
    while pending:
        os.close(pending.pop()[1])
if actual != set(expected) | expected_dirs:
    raise RuntimeError("workspace path set mismatch")
probe = os.path.join(probe_root, ".zeus-audit-write-probe")
descriptor = os.open(probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
try:
    probe_stat = os.fstat(descriptor)
    if (
        not stat.S_ISREG(probe_stat.st_mode)
        or stat.S_IMODE(probe_stat.st_mode) != 0o600
        or probe_stat.st_uid != expected_entry_uid
        or probe_stat.st_gid != expected_entry_gid
    ):
        raise RuntimeError("workspace write probe metadata mismatch")
    os.write(descriptor, b"probe")
finally:
    os.close(descriptor)
os.unlink(probe)
try:
    os.lstat(probe)
except FileNotFoundError:
    pass
else:
    raise RuntimeError("workspace write probe could not be deleted")
""".strip()
