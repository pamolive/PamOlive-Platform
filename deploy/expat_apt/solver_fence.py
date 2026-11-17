"""Linux x86-64 solver-only network denial; not a universal root sandbox."""

import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path

ROLE = "apt-simulate-14-network-denied-v1"
HERE = Path("/opt/expat-apt")
PYTHON = "/usr/local/bin/python3.12"
APT = "/usr/bin/apt-get"
CONFIG = Path("/expat-apt-work/solver.conf")
WORK = Path("/expat-apt-work")
PROOF = Path("/expat-apt-proof")
IDENTITY = ("dev", "ino", "mode", "uid", "gid", "nlink", "size", "mtime_ns", "ctime_ns")
TABLE_SHA256 = "4c30abea9a4b69f3409bea7a0c910a8c8feb9a44b22a448b5c82f2bfdd8249c8"
# Linux v6.8 arch/x86/entry/syscalls/syscall_64.tbl, common/64 entries only.
# Generated from the pinned primary table; reserved holes and future numbers refuse.
KNOWN_SYSCALLS = (
    0,
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
    12,
    13,
    14,
    15,
    16,
    17,
    18,
    19,
    20,
    21,
    22,
    23,
    24,
    25,
    26,
    27,
    28,
    29,
    30,
    31,
    32,
    33,
    34,
    35,
    36,
    37,
    38,
    39,
    40,
    41,
    42,
    43,
    44,
    45,
    46,
    47,
    48,
    49,
    50,
    51,
    52,
    53,
    54,
    55,
    56,
    57,
    58,
    59,
    60,
    61,
    62,
    63,
    64,
    65,
    66,
    67,
    68,
    69,
    70,
    71,
    72,
    73,
    74,
    75,
    76,
    77,
    78,
    79,
    80,
    81,
    82,
    83,
    84,
    85,
    86,
    87,
    88,
    89,
    90,
    91,
    92,
    93,
    94,
    95,
    96,
    97,
    98,
    99,
    100,
    101,
    102,
    103,
    104,
    105,
    106,
    107,
    108,
    109,
    110,
    111,
    112,
    113,
    114,
    115,
    116,
    117,
    118,
    119,
    120,
    121,
    122,
    123,
    124,
    125,
    126,
    127,
    128,
    129,
    130,
    131,
    132,
    133,
    134,
    135,
    136,
    137,
    138,
    139,
    140,
    141,
    142,
    143,
    144,
    145,
    146,
    147,
    148,
    149,
    150,
    151,
    152,
    153,
    154,
    155,
    156,
    157,
    158,
    159,
    160,
    161,
    162,
    163,
    164,
    165,
    166,
    167,
    168,
    169,
    170,
    171,
    172,
    173,
    174,
    175,
    176,
    177,
    178,
    179,
    180,
    181,
    182,
    183,
    184,
    185,
    186,
    187,
    188,
    189,
    190,
    191,
    192,
    193,
    194,
    195,
    196,
    197,
    198,
    199,
    200,
    201,
    202,
    203,
    204,
    205,
    206,
    207,
    208,
    209,
    210,
    211,
    212,
    213,
    214,
    215,
    216,
    217,
    218,
    219,
    220,
    221,
    222,
    223,
    224,
    225,
    226,
    227,
    228,
    229,
    230,
    231,
    232,
    233,
    234,
    235,
    236,
    237,
    238,
    239,
    240,
    241,
    242,
    243,
    244,
    245,
    246,
    247,
    248,
    249,
    250,
    251,
    252,
    253,
    254,
    255,
    256,
    257,
    258,
    259,
    260,
    261,
    262,
    263,
    264,
    265,
    266,
    267,
    268,
    269,
    270,
    271,
    272,
    273,
    274,
    275,
    276,
    277,
    278,
    279,
    280,
    281,
    282,
    283,
    284,
    285,
    286,
    287,
    288,
    289,
    290,
    291,
    292,
    293,
    294,
    295,
    296,
    297,
    298,
    299,
    300,
    301,
    302,
    303,
    304,
    305,
    306,
    307,
    308,
    309,
    310,
    311,
    312,
    313,
    314,
    315,
    316,
    317,
    318,
    319,
    320,
    321,
    322,
    323,
    324,
    325,
    326,
    327,
    328,
    329,
    330,
    331,
    332,
    333,
    334,
    424,
    425,
    426,
    427,
    428,
    429,
    430,
    431,
    432,
    433,
    434,
    435,
    436,
    437,
    438,
    439,
    440,
    441,
    442,
    443,
    444,
    445,
    446,
    447,
    448,
    449,
    450,
    451,
    452,
    453,
    454,
    455,
    456,
    457,
    458,
    459,
    460,
    461,
)
NETWORK_DENIED = frozenset(
    (41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 288, 299, 307)
)
ESCAPE_DENIED = frozenset((101, 310, 311, 425, 426, 427, 438))
ARCH_X86_64 = 0xC000003E
X32_BIT = 0x40000000
ALLOW = 0x7FFF0000
KILL = 0x80000000
DENY = 0x00050001  # SECCOMP_RET_ERRNO | EPERM; never fake syscall success.
SOLVER_CONFIG_SHA = "c734989af6845745fd85bf2608c2b264766672cda138773d40be24b47a9830b4"
APT_ARGV = (
    APT,
    "--simulate",
    "--no-remove",
    "--no-install-recommends",
    "install",
    "build-essential",
    "binutils",
    "patch",
    "gpg=2.4.7-21+deb13u1+b5",
    "dpkg-dev",
    "debhelper",
    "autoconf",
    "automake",
    "libtool",
    "pkg-config",
    "docbook-to-man",
    "docbook2x",
    "libexpat1-dev=2.9.0-1~deb13u1",
    "ca-certificates",
)
ENV = {
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG": "C",
    "LC_ALL": "C",
    "HOME": str(WORK),
    "APT_CONFIG": str(CONFIG),
    "DEBIAN_FRONTEND": "noninteractive",
}


def need(value, code):
    if not value:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(row):
    return tuple(getattr(row, "st_" + name) for name in IDENTITY)


def digest(value):
    return type(value) is str and re.fullmatch("[a-f0-9]{64}", value) is not None


def captured_file(path, cap, *, keep=False, executable=False):
    path = Path(path)
    for parent in (path.parent, *path.parent.parents):
        row = parent.lstat()
        need(
            stat.S_ISDIR(row.st_mode) and row.st_uid == 0 and not row.st_mode & 0o022,
            "fence_parent",
        )
    before = path.lstat()
    need(
        stat.S_ISREG(before.st_mode)
        and before.st_nlink == 1
        and before.st_uid == before.st_gid == 0
        and not before.st_mode & 0o6022
        and 0 < before.st_size <= cap,
        "fence_file",
    )
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    retained = False
    try:
        need(identity(os.fstat(fd)) == identity(before), "fence_FD")
        chunks, size = [], 0
        while True:
            block = os.read(fd, min(65536, cap + 1 - size))
            if not block:
                break
            chunks.append(block)
            size += len(block)
            need(size <= cap, "fence_file_cap")
        raw = b"".join(chunks)
        need(
            len(raw) == before.st_size
            and identity(os.fstat(fd)) == identity(before)
            and identity(path.lstat()) == identity(before),
            "fence_changed",
        )
        need(not executable or raw.startswith(b"\x7fELF"), "fence_not_ELF")
        if keep:
            retained = True
            return fd, raw, identity(before)
        return raw, identity(before)
    finally:
        if not retained:
            os.close(fd)


def program():
    need(
        type(KNOWN_SYSCALLS) is tuple
        and len(set(KNOWN_SYSCALLS)) == len(KNOWN_SYSCALLS)
        and all(type(n) is int and 0 <= n < 512 for n in KNOWN_SYSCALLS),
        "fence_table",
    )
    rows = [
        (0x20, 0, 0, 4),
        (0x15, 1, 0, ARCH_X86_64),
        (0x06, 0, 0, KILL),
        (0x20, 0, 0, 0),
        (0x45, 0, 1, X32_BIT),
        (0x06, 0, 0, DENY),
    ]
    for nr in KNOWN_SYSCALLS:
        if nr not in NETWORK_DENIED | ESCAPE_DENIED:
            rows.extend(((0x15, 0, 1, nr), (0x06, 0, 0, ALLOW)))
    rows.append((0x06, 0, 0, DENY))
    need(len(rows) <= 4096, "fence_program_cap")
    return tuple(rows)


def filter_sha():
    return sha(json.dumps(program(), separators=(",", ":")).encode())


def model_filter(arch, nr):
    """Pure interpreter of the exact emitted cBPF subset; never a kernel proof."""
    accumulator = cursor = 0
    rows = program()
    for _ in range(len(rows) + 1):
        code, jt, jf, value = rows[cursor]
        if code == 0x20:
            accumulator = arch if value == 4 else nr
        elif code == 0x15:
            cursor += jt if accumulator == value else jf
        elif code == 0x45:
            cursor += jt if accumulator & value else jf
        elif code == 0x06:
            return value
        else:
            raise ValueError("fence_model_opcode")
        cursor += 1
    raise ValueError("fence_model_unterminated")


class LinuxAPI:
    """Loaded only at the native Linux entrypoint, never by pure tests."""

    def __init__(self):
        import ctypes

        self.c = ctypes
        need(ctypes.sizeof(ctypes.c_void_p) == 8, "fence_pointer_ABI")
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.libc.syscall.restype = ctypes.c_long
        self.libc.prctl.argtypes = [ctypes.c_int] + [ctypes.c_ulong] * 4
        self.libc.prctl.restype = ctypes.c_int

    def close_others(self):
        c = self.c
        need(
            self.libc.syscall(c.c_long(436), c.c_uint(3), c.c_uint(0xFFFFFFFF), c.c_uint(2)) == 0,
            "fence_close_range",
        )

    def install(self, rows):
        c = self.c

        class Instruction(c.Structure):
            _fields_ = [("code", c.c_ushort), ("jt", c.c_ubyte), ("jf", c.c_ubyte), ("k", c.c_uint)]

        class Program(c.Structure):
            _fields_ = [("length", c.c_ushort), ("filter", c.POINTER(Instruction))]

        need(
            c.sizeof(Instruction) == 8 and c.sizeof(Program) == 16 and Program.filter.offset == 8,
            "fence_structure_ABI",
        )
        instructions = (Instruction * len(rows))(*(Instruction(*r) for r in rows))
        argument = Program(len(rows), instructions)
        need(self.libc.prctl(38, 1, 0, 0, 0) == 0, "fence_NNP_set")
        need(self.libc.prctl(39, 0, 0, 0, 0) == 1, "fence_NNP_get")
        need(self.libc.prctl(22, 2, c.addressof(argument), 0, 0) == 0, "fence_install")
        need(self.libc.prctl(21, 0, 0, 0, 0) == 2, "fence_mode")

    def denied(self, nr, *arguments):
        self.c.set_errno(0)
        result = self.libc.syscall(self.c.c_long(nr), *[self.c.c_long(n) for n in arguments])
        return result == -1 and self.c.get_errno() == 1

    def execfd(self, fd, argv, env):
        """Direct execveat(AT_EMPTY_PATH), no libc fexecve/proc-path fallback."""
        need(
            type(fd) is int and fd >= 3 and type(argv) is list and type(env) is dict,
            "fence_exec_arguments",
        )
        need(
            all(type(s) is str and "\x00" not in s for s in argv)
            and all(
                type(k) is str and type(v) is str and "=" not in k and "\x00" not in k + v
                for k, v in env.items()
            ),
            "fence_exec_strings",
        )
        c = self.c
        args = (c.c_char_p * (len(argv) + 1))(*(s.encode("ascii") for s in argv), None)
        variables = (c.c_char_p * (len(env) + 1))(
            *((k + "=" + v).encode("ascii") for k, v in env.items()), None
        )
        self.libc.syscall(
            c.c_long(322), c.c_int(fd), c.c_char_p(b""), args, variables, c.c_int(0x1000)
        )
        raise ValueError("fence_execveat_returned")


def prepare_kernel(api):
    need(
        sys.platform == "linux"
        and os.uname().machine == "x86_64"
        and os.getuid() == os.geteuid() == 0,
        "fence_platform",
    )
    tasks = tuple(Path("/proc/self/task").iterdir())
    need(len(tasks) == 1 and tasks[0].name == str(os.getpid()), "fence_threads")
    stdin, stdout, stderr = [os.fstat(n) for n in (0, 1, 2)]
    need(
        stat.S_ISCHR(stdin.st_mode)
        and stdin.st_rdev == os.makedev(1, 3)
        and stat.S_ISFIFO(stdout.st_mode)
        and stat.S_ISFIFO(stderr.st_mode),
        "fence_stdio",
    )
    api.close_others()


def emit(path, packet):
    raw = (json.dumps(packet, separators=(",", ":")) + "\n").encode()
    need(len(raw) <= 4096, "fence_packet_cap")
    row = path.parent.lstat()
    need(
        stat.S_ISDIR(row.st_mode) and row.st_uid == row.st_gid == 0 and not row.st_mode & 0o077,
        "fence_proof_parent",
    )
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o400)
    try:
        need(os.write(fd, raw) == len(raw), "fence_short_write")
        os.fsync(fd)
        need(identity(os.fstat(fd)) == identity(path.lstat()), "fence_packet_changed")
    finally:
        os.close(fd)


def launch_argv(helper_sha, code_sha, apt_sha, python_sha, config_sha, ordinal):
    need(
        all(digest(v) for v in (helper_sha, code_sha, apt_sha, python_sha, config_sha))
        and type(ordinal) is int
        and 1 <= ordinal <= 16,
        "fence_launch_role",
    )
    return [
        PYTHON,
        "-I",
        "-B",
        "-S",
        "-c",
        LOADER,
        helper_sha,
        code_sha,
        apt_sha,
        python_sha,
        config_sha,
        str(ordinal),
    ]


def validate_packet(packet, *, pid, code_sha, helper_sha, python_pin, apt_pin, ordinal):
    need(
        type(packet) is dict
        and set(packet)
        == {
            "schema",
            "role",
            "pid",
            "code_pins_sha256",
            "helper_sha256",
            "python_sha256",
            "python_identity",
            "APT_sha256",
            "APT_identity",
            "config_sha256",
            "filter_sha256",
            "NNP",
            "seccomp_mode",
            "close_range_UNSHARE",
            "stdio",
            "ordinal",
            "build_verified",
            "materials_complete",
            "operational_GO",
        },
        "fence_packet_keys",
    )
    need(
        packet["schema"] == "pamolive.expat-APT-network-fence-DATA/1"
        and packet["role"] == ROLE
        and type(packet["pid"]) is int
        and packet["pid"] == pid
        and type(packet["ordinal"]) is int
        and packet["ordinal"] == ordinal
        and packet["code_pins_sha256"] == code_sha
        and packet["helper_sha256"] == helper_sha
        and packet["python_sha256"] == python_pin[0]
        and packet["APT_sha256"] == apt_pin[0]
        and packet["config_sha256"] == SOLVER_CONFIG_SHA
        and packet["filter_sha256"] == filter_sha()
        and type(packet["NNP"]) is int
        and packet["NNP"] == 1
        and type(packet["seccomp_mode"]) is int
        and packet["seccomp_mode"] == 2
        and packet["close_range_UNSHARE"] is True
        and packet["stdio"] == ["DEVNULL", "PIPE", "PIPE"]
        and all(
            packet[k] is False for k in ("build_verified", "materials_complete", "operational_GO")
        ),
        "fence_packet_context",
    )
    for key, pin in (("python_identity", python_pin), ("APT_identity", apt_pin)):
        need(
            type(packet[key]) is list
            and len(packet[key]) == len(IDENTITY)
            and all(type(n) is int for n in packet[key])
            and tuple(packet[key]) == pin[1],
            "fence_packet_identity",
        )


def validate_native_summary(packet, code_sha, pins):
    need(
        type(packet) is dict
        and set(packet)
        == {
            "schema",
            "state",
            "code_pins_sha256",
            "helper_sha256",
            "native_source_sha256",
            "filter_sha256",
            "cases",
            "H1",
            "build_verified",
            "materials_complete",
            "all_OS_descendants_released",
            "operational_GO",
        },
        "fence_native_keys",
    )
    need(
        packet["schema"] == "pamolive.expat-solver-fence-native-DATA/1"
        and packet["state"] == "COMPLETE_DATA_ONLY"
        and packet["code_pins_sha256"] == code_sha
        and packet["helper_sha256"] == pins["solver_fence.py"]
        and packet["native_source_sha256"] == pins["native_fence_tests.py"]
        and packet["filter_sha256"] == filter_sha()
        and packet["cases"] == ["syscalls", "exec"]
        and type(packet["H1"]) is list
        and len(packet["H1"]) == 2
        and all(
            packet[k] is False
            for k in (
                "build_verified",
                "materials_complete",
                "all_OS_descendants_released",
                "operational_GO",
            )
        ),
        "fence_native_context",
    )
    for row in packet["H1"]:
        need(
            type(row) is dict
            and set(row)
            == {
                "spawn_attempted",
                "pid",
                "returncode",
                "reason",
                "exception_type",
                "killed_owned_child",
                "owned_child_reaped",
                "drains_complete",
                "cleanup_exception_type",
                "stdout_bytes",
                "stderr_bytes",
            }
            and row["spawn_attempted"] is True
            and type(row["pid"]) is int
            and row["pid"] > 0
            and type(row["returncode"]) is int
            and row["returncode"] == 0
            and row["reason"] is row["exception_type"] is row["cleanup_exception_type"] is None
            and row["owned_child_reaped"] is row["drains_complete"] is True
            and row["killed_owned_child"] is False
            and type(row["stdout_bytes"]) is int
            and 0 < row["stdout_bytes"] <= 4096
            and type(row["stderr_bytes"]) is int
            and row["stderr_bytes"] == 0,
            "fence_native_H1",
        )


def main():
    need(len(sys.argv) == 7, "fence_arguments")
    helper_sha, code_sha, apt_sha, python_sha, config_sha, number = sys.argv[1:]
    need(
        all(digest(v) for v in (helper_sha, code_sha, apt_sha, python_sha, config_sha))
        and re.fullmatch("[1-9]|1[0-6]", number) is not None,
        "fence_arguments",
    )
    need(globals().get("CAPTURED_HELPER_SHA") == helper_sha, "fence_captured_source")
    pins_raw, _ = captured_file(HERE / "code-pins.json", 16384)
    pins = json.loads(pins_raw)
    need(sha(pins_raw) == code_sha and pins["solver_fence.py"] == helper_sha, "fence_code_pins")
    python_raw, python_identity = captured_file(PYTHON, 64 * 1024**2, executable=True)
    running = os.stat("/proc/self/exe")
    need(
        sha(python_raw) == python_sha
        and identity(running) == python_identity
        and sys.flags.isolated == 1
        and sys.flags.no_site == 1
        and sys.dont_write_bytecode,
        "fence_interpreter",
    )
    config_raw, _ = captured_file(CONFIG, 16384)
    need(sha(config_raw) == config_sha == SOLVER_CONFIG_SHA, "fence_configuration")
    api = LinuxAPI()
    prepare_kernel(api)  # closes all >=3 before the only retained payload FD is opened.
    fd, raw, apt_identity = captured_file(APT, 64 * 1024**2, keep=True, executable=True)
    try:
        need(
            fd >= 3
            and not os.get_inheritable(fd)
            and sha(raw) == apt_sha
            and callable(getattr(api, "execfd", None)),
            "fence_exec_FD_required",
        )
        api.install(program())
        packet = {
            "schema": "pamolive.expat-APT-network-fence-DATA/1",
            "role": ROLE,
            "pid": os.getpid(),
            "code_pins_sha256": code_sha,
            "helper_sha256": helper_sha,
            "python_sha256": python_sha,
            "python_identity": python_identity,
            "APT_sha256": apt_sha,
            "APT_identity": apt_identity,
            "config_sha256": config_sha,
            "filter_sha256": filter_sha(),
            "NNP": 1,
            "seccomp_mode": 2,
            "close_range_UNSHARE": True,
            "stdio": ["DEVNULL", "PIPE", "PIPE"],
            "ordinal": int(number),
            "build_verified": False,
            "materials_complete": False,
            "operational_GO": False,
        }
        # Recheck the retained FD and path immediately before the sole FD exec.
        need(
            identity(os.fstat(fd)) == apt_identity and identity(Path(APT).lstat()) == apt_identity,
            "fence_exec_changed",
        )
        emit(PROOF / ("command-" + number + "-fence.json"), packet)
        api.execfd(fd, list(APT_ARGV), dict(ENV))
        raise ValueError("fence_exec_returned")
    finally:
        os.close(fd)


# The parent executes a fixed loader, not a second mutable opening of the helper.
# Capture/hash/compile use the same bytes. No user-supplied path or Python fragment.
LOADER = """import hashlib,os,stat,sys
p='/opt/expat-apt/solver_fence.py'
f=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
b=os.fstat(f)
def fields(r):
 return (r.st_dev,r.st_ino,r.st_mode,r.st_uid,r.st_gid,r.st_nlink,
         r.st_size,r.st_mtime_ns,r.st_ctime_ns)
assert (stat.S_ISREG(b.st_mode) and b.st_uid==b.st_gid==0 and b.st_nlink==1
        and not b.st_mode&0o6022 and 0<b.st_size<=131072)
raw=b''
while len(raw)<=131072:
 chunk=os.read(f, min(65536,131073-len(raw)))
 if not chunk:break
 raw+=chunk
assert len(raw)==b.st_size and fields(os.fstat(f))==fields(b)==fields(os.lstat(p))
os.close(f)
assert hashlib.sha256(raw).hexdigest()==sys.argv[1]
for parent in ('/opt/expat-apt','/opt','/'):
 r=os.lstat(parent);assert stat.S_ISDIR(r.st_mode) and r.st_uid==0 and not r.st_mode&0o022
scope={'__name__':'__main__','__file__':p,'CAPTURED_HELPER_SHA':sys.argv[1]}
exec(compile(raw,p,'exec'),scope)
"""


if __name__ == "__main__":
    try:
        main()
    except BaseException:
        # Never emit exception text, helper arguments or environment.
        sys.stderr.write('{"schema":"pamolive.expat-fence-failure/1","state":"UNKNOWN"}\n')
        raise SystemExit(42) from None
