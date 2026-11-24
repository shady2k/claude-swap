"""Linux-only, opt-in launcher and independent syscall audit for the test stand.

For a trusted checkout, an ordinary user with passwordless sudo can set
``CSWAP_STAND_SUDO=1`` and ``CSWAP_STAND_RUN_AS=$(id -u):$(id -g)``.
Only namespace setup uses root; strace and all workers run as the caller.
The setup imports this checkout under sudo; do not use it with untrusted code.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import runpy
import shutil
import signal
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from tempfile import mkdtemp


OPT_IN = "CSWAP_TEST_STAND"
DNS_SINK = ("127.0.0.53", 53)
HOSTS = "127.0.0.1 localhost\n::1 localhost\n"
RESOLV_CONF = f"nameserver {DNS_SINK[0]}\noptions timeout:1 attempts:1\n"
NSSWITCH = "hosts: files dns\n"
PROJECT = Path(__file__).resolve().parents[1]
SYSTEM_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
TIMEOUT = 30  # seconds, including setup, tracing and test execution

Role = tuple[str, ...]  # Fixed module and arguments, identified by execve.
Target = tuple[str, int]
DIRECT_SCENARIOS = ("direct_success", "direct_refused")
HISTORY_SCENARIOS = ("history_success", "history_503")
MOCK_SCENARIOS = (
    "positive", "cli_positive", "direct", "denied_connect", "shim_positive", "shim_direct",
    *DIRECT_SCENARIOS,
    "f15_setup_default", "f15_setup_probe", "f15_oauth_gate",
)
MOCK_CLI_CONTROLS = ("missing_endpoint", "malformed_endpoint")
SHIM_REFUSALS = (
    "missing_endpoint", "loopback_endpoint", "public_endpoint", "public_base", "public_proxy",
    "unlisted_claude", "project_env", "user_env", "client_settings", "auth", "update", "unknown", "bypass",
)
_SHIM_SPAWN_ROLES = {
    *(("stand_mock", "client", name) for name in ("shim_positive", "shim_direct", *DIRECT_SCENARIOS)),
    *(("stand_shim", name) for name in (*SHIM_REFUSALS, "escape", *HISTORY_SCENARIOS)),
}
ROOT_ROLES = {
    *(("stand_mock", scenario) for scenario in (*MOCK_SCENARIOS, *MOCK_CLI_CONTROLS)),
    *(("stand_linux_control", name) for name in ("normal", "dns", "failed")),
    *(("stand_shim", name) for name in (*SHIM_REFUSALS, "escape", *HISTORY_SCENARIOS)),
}


def _child_roles(role: Role) -> set[Role]:
    if role == ("stand_linux_control", "dns"):
        return {("stand_linux_control", "query")}
    if len(role) == 2 and role[0] == "stand_mock" and role[1] in MOCK_SCENARIOS:
        scenario = role[1]
        server = ("stand_mock", "serve", scenario) if scenario in DIRECT_SCENARIOS else ("stand_mock", "serve")
        return {server, ("stand_mock", "client", scenario)}
    return set()


WORKER_ROLES = ROOT_ROLES.union(*(_child_roles(role) for role in ROOT_ROLES))
MOCK_SERVER_ROLES = {role for role in WORKER_ROLES if role[:2] == ("stand_mock", "serve")}
TLS_SERVER_ROLES = MOCK_SERVER_ROLES | {("stand_shim", name) for name in HISTORY_SCENARIOS}


class StandError(RuntimeError):
    """The stand could not establish isolation or produce a complete trace."""


def _tool(name: str) -> str:
    result = shutil.which(name, path=SYSTEM_PATH)
    if not result:
        raise StandError(f"missing stand executable in {SYSTEM_PATH}: {name}")
    return result


def openssl_path() -> str:
    return _tool("openssl")


def _namespace(name: str) -> str:
    return os.readlink(f"/proc/self/ns/{name}")


def require_isolation() -> None:
    """Refuse to create stand sockets without the launcher's namespace setup."""
    if sys.platform != "linux" or os.environ.get(OPT_IN) != "1":
        raise StandError("the network stand is Linux-only and opt-in")
    if os.environ.get("CLAUDE_SWAP_TEST_MODE") != "1":
        raise StandError("test mode is not enabled in the network stand")
    for name in ("net", "mnt"):
        outer = os.environ.get(f"CSWAP_STAND_OUTER_{name.upper()}")
        if not outer or _namespace(name) == outer:
            raise StandError(f"the stand is not in a fresh {name} namespace")
    links = Path("/proc/self/net/dev").read_text().splitlines()[2:]
    if [row.split(":", 1)[0].strip() for row in links] != ["lo"]:
        raise StandError("the stand does not have only loopback")
    if Path("/etc/resolv.conf").read_text() != RESOLV_CONF or (
        Path("/etc/nsswitch.conf").read_text() != NSSWITCH
    ):
        raise StandError("the stand resolver is not private")
    receipt = Path(os.environ["CSWAP_STAND_ROOT"]) / "isolated"
    if receipt.read_text().splitlines() != [_namespace("net"), _namespace("mnt")]:
        raise StandError("the stand did not pass the topology check")


def _checked(*argv: str) -> str:
    result = subprocess.run(argv, capture_output=True, text=True)
    if result.returncode:
        raise StandError(f"namespace setup: {argv[0]} failed: {result.stderr.strip()}")
    return result.stdout


def _enter(module: str, args: list[str]) -> int:
    # unshare must have succeeded before touching any mounts or links.
    for name in ("net", "mnt"):
        if _namespace(name) == os.environ[f"CSWAP_STAND_OUTER_{name.upper()}"]:
            raise StandError(f"unshare did not create a {name} namespace")
    run_dir = Path(os.environ["CSWAP_STAND_ROOT"])
    mount = _tool("mount")
    for name in ("hosts", "resolv.conf", "nsswitch.conf"):
        target = f"/etc/{name}"
        _checked(mount, "--bind", str(run_dir / name), target)
        _checked(mount, "-o", "remount,bind,ro", target)
    # glibc can consult nscd before reading nsswitch.conf. Mask its socket
    # directory if present, without hiding a resolv.conf symlink into /run.
    for target in {Path("/run/nscd").resolve(), Path("/var/run/nscd").resolve()}:
        if target.is_dir():
            _checked(mount, "--bind", str(run_dir / "empty"), str(target))
            _checked(mount, "-o", "remount,bind,ro", str(target))

    ip = _tool("ip")
    _checked(ip, "link", "set", "lo", "up")
    links = json.loads(_checked(ip, "-j", "address", "show"))
    if len(links) != 1 or links[0]["ifname"] != "lo" or not {
        "LOOPBACK", "UP",
    }.issubset(links[0]["flags"]):
        raise StandError("the stand requires a single active loopback link")
    for addr in links[0]["addr_info"]:
        if not ipaddress.ip_address(addr["local"]).is_loopback:
            raise StandError("the stand has a non-loopback address")
    for family in ("-4", "-6"):
        for route in json.loads(_checked(ip, "-j", family, "route", "show", "table", "all")):
            if (
                route.get("dev") != "lo" or "gateway" in route
                or not _is_loopback_network(route.get("dst", "default"))
            ):
                raise StandError("the stand has a route outside loopback")
    if identity := os.environ.get("CSWAP_STAND_RUN_AS"):
        # Port 53 is private to this namespace. Keep the DNS detector's
        # low-port sink usable after dropping privileges to the caller.
        Path("/proc/sys/net/ipv4/ip_unprivileged_port_start").write_text("53\n", encoding="ascii")
        uid, gid = identity.split(":")
        setpriv = _tool("setpriv")
        os.execv(setpriv, [
            setpriv, "--reuid", uid, "--regid", gid, "--clear-groups", "--no-new-privs",
            sys.executable, "-Es", "-m", "tests.stand_linux", "trace", module, *args,
        ])
    return _trace(module, args)


def _trace(module: str, args: list[str]) -> int:
    if (identity := os.environ.get("CSWAP_STAND_RUN_AS")) and (
        os.geteuid() == 0 or os.getegid() == 0 or identity != f"{os.geteuid()}:{os.getegid()}"
    ):
        raise StandError("stand could not drop to the requested uid:gid")
    run_dir = Path(os.environ["CSWAP_STAND_ROOT"])
    (run_dir / "isolated").write_text(f"{_namespace('net')}\n{_namespace('mnt')}\n")
    require_isolation()
    result = subprocess.run([
        _tool("strace"), "-ff", "--kill-on-exit", "-yy", "-s", "256",
        "-o", str(run_dir / "trace"),
        "-e", "trace=%network,%process,prctl,io_uring_setup,unshare,setns",
        "-e", "abbrev=!sendmsg,sendmmsg",
        "-e", "inject=io_uring_setup,unshare,setns:error=EPERM",
        *worker_argv(module, *args),
    ])
    (run_dir / "trace-completed").write_text(str(result.returncode))
    return result.returncode


def _is_loopback_network(dst: str) -> bool:
    try:
        net = ipaddress.ip_network(dst)
    except ValueError:
        return False
    return net.subnet_of(ipaddress.ip_network("127.0.0.0/8" if net.version == 4 else "::1/128"))


def worker_argv(module: str, *args: str) -> list[str]:
    return [sys.executable, "-Es", "-m", "tests.stand_linux", "worker", module, *args]


def _worker(module: str, args: list[str]) -> None:
    require_isolation()
    role = (module, *args)
    if role not in WORKER_ROLES:
        raise StandError("stand worker is not allowlisted")
    commands = {tuple(worker_argv(*child)) for child in _child_roles(role)}
    openssl = openssl_path() if role in TLS_SERVER_ROLES else None
    destinations = next(
        ({tuple(target) for target in targets} for name, targets in
         json.loads(os.environ["CSWAP_STAND_DESTINATIONS"]) if tuple(name) == role),
        set(),
    )

    blocked_resolver = None
    supervision_used = False
    supervisor_pid = os.getpid()
    if role in _SHIM_SPAWN_ROLES:
        from tests.stand_shim import command, history_start_command

        shim_commands = [command(role[-1])]
        if role[-1] in HISTORY_SCENARIOS:
            shim_commands.append(history_start_command())
    else:
        shim_commands = []

    def restrict_worker(event: str, values: tuple) -> None:
        nonlocal blocked_resolver, supervision_used
        if event == "os.fork" and role == ("stand_mock", "client", "cli_positive") and not supervision_used:
            from claude_swap import paths, session, spawn

            frame = sys._getframe(1)
            profile = session.session_dir_for(paths.get_backup_root(), "1", "account@example.test")
            records = [json.loads(path.read_text()) for path in
                       (paths.get_backup_root() / "profile-ownership" / "launches").glob("*.json")]
            running = [entry for entry in records if entry.get("state") == "running"
                       and entry.get("pid") == supervisor_pid and entry.get("ownerPid") == supervisor_pid
                       and entry.get("profile") == str(profile) and entry.get("accountNum") == "1"]
            if (os.getpid() == supervisor_pid and frame.f_code is spawn._Supervision.wait.__code__
                    and Path(frame.f_code.co_filename).resolve() == PROJECT / "src" / "claude_swap" / "spawn.py"
                    and len(running) == 1):
                supervision_used = True
                return
        # Mock workers use numeric addresses and must never ask the resolver.
        # The standalone controls deliberately exercise strace alone.
        if module == "stand_mock":
            if event in {
                "socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyaddr",
                "socket.getnameinfo",
            }:
                blocked_resolver = event
                raise StandError(f"stand resolver call not allowed for {role!r}: {event}")
            if event == "socket.connect":
                _, address = values
                if not isinstance(address, tuple) or address[:2] not in destinations:
                    raise StandError(f"stand connect destination not allowed for {role!r}")
        if event == "subprocess.Popen":
            executable, argv, _cwd, _env = values
            if executable == "claude" and argv in shim_commands:
                return
            if (
                isinstance(argv, (list, tuple)) and argv and argv[0] == executable
                and (tuple(argv) in commands or (
                    executable == openssl and len(argv) > 1 and argv[1] in {"req", "x509"}
                ))
            ):
                return
            raise StandError("stand subprocess executable is not allowlisted")
        if event in {"os.exec", "os.posix_spawn", "os.system", "os.fork", "os.forkpty", "os.spawn"}:
            raise StandError("stand processes must use the guarded subprocess launcher")

    sys.addaudithook(restrict_worker)
    sys.argv = [f"tests.{module}", *args]
    try:
        if module == "stand_shim":
            from tests.stand_shim import main

            raise SystemExit(main(args[0]))
        runpy.run_module(f"tests.{module}", run_name="__main__")
    finally:
        if blocked_resolver is not None:
            # A caught refusal is still an attempted lookup.
            raise StandError(f"stand blocked resolver call: {blocked_resolver}") from None


@dataclass(frozen=True)
class Attempt:
    pid: int
    syscall: str
    role: Role
    target: Target | None
    result: str
    permitted: bool

    @property
    def dns(self) -> bool:
        return self.target is not None and self.target[1] == 53


@dataclass(frozen=True)
class StandRun:
    stdout: str
    stderr: str
    returncode: int
    attempts: tuple[Attempt, ...]
    violations: tuple[str, ...]
    shim_execs: tuple[str, ...]

    def require_clean(self) -> None:
        if self.violations:
            raise AssertionError("network stand audit failed:\n" + "\n".join(self.violations))


# -yy supplies the kernel's peer endpoint for connected sends with no sockaddr.
_INET = re.compile(
    r'sin(?:6)?_port=htons\((\d+)\).*?(?:inet_addr\("|inet_pton\(AF_INET6, ")([^"]+)"'
)
_PEER = re.compile(r'<(TCP|UDP)(?:v6)?:\[(.+?)->(.+?)\]>')
_EXEC = re.compile(r'^execve\("([^"]+)", (\[.*?\]), 0x')
_SYSCALL = re.compile(r'^(\w+)\(')
_RESULT = re.compile(r'\)\s+= (.+)$')
_END = re.compile(r'^\+\+\+ (?:exited with|killed by) ')


def _endpoint(text: str) -> tuple[str, int]:
    host, port = text.rsplit(":", 1)
    return host.strip("[]"), int(port)


def _targets(call: str, line: str) -> list[tuple[Target | None, Target | None]]:
    """Return (destination, connected TCP source if known) for each message."""
    if call in {"sendmsg", "sendmmsg"}:
        addresses = re.findall(r"msg_name=(NULL|\{sa_family=[^}]*\}|0x[0-9a-f]+)", line)
    else:
        address = re.search(r", (NULL|\{sa_family=[^}]*\}|0x[0-9a-f]+), \d+\)\s+=", line)
        addresses = [address[1]] if address else []
    targets = []
    for addr in addresses:
        if match := _INET.search(addr):
            targets.append(((match[2], int(match[1])), None))
        elif addr == "NULL" and call != "connect" and (peer := _PEER.search(line)):
            try:
                source = _endpoint(peer[2]) if peer[1] == "TCP" else None
                targets.append((_endpoint(peer[3]), source))
            except ValueError:
                targets.append((None, None))
        else:
            targets.append((None, None))
    return targets or [(None, None)]


def _exec_command(line: str) -> tuple[str, list[str]] | None:
    match = _EXEC.match(line)
    if match:
        try:
            return match[1], json.loads(match[2])
        except ValueError:
            pass
    return None


def _exec_argv(line: str) -> list[str] | None:
    command = _exec_command(line)
    if command and command[1] and command[0] == command[1][0]:
        return command[1]
    return None


def _audit(
    run_dir: Path, root_role: Role, allowed: dict[Role, set[Target]],
    listeners: dict[Role, set[Target]],
) -> tuple[tuple[Attempt, ...], tuple[str, ...], tuple[str, ...]]:
    by_pid = {
        int(path.suffix[1:]): path.read_text().splitlines() for path in run_dir.glob("trace.*")
    }
    if not by_pid:
        raise StandError("strace did not produce any trace files")
    # Threads and forked children inherit the calling process's role until exec.
    parents = {}
    for pid, lines in by_pid.items():
        if not lines or not _END.match(lines[-1]):
            raise StandError(f"incomplete trace for pid {pid}")
        for line in lines:
            if line.startswith(("clone(", "clone3(", "fork(", "vfork(")):
                result = _RESULT.search(line)
                if result and result[1].isdigit() and int(result[1]) > 0:
                    child = int(result[1])
                    if child not in by_pid:
                        raise StandError(f"missing strace for pid {child}")
                    parents[child] = pid
    roots = set(by_pid) - parents.keys()
    if len(roots) != 1:
        raise StandError("strace did not account for the whole process tree")
    root = next(iter(roots))
    entry = by_pid[root][0]
    if _exec_argv(entry) != worker_argv(*root_role) or not entry.endswith(" = 0"):
        raise StandError("strace missed the worker entry point")

    attempts = []
    violations = []
    openssl = shutil.which("openssl", path=SYSTEM_PATH)
    child_commands = {tuple(worker_argv(*role)): role for role in _child_roles(root_role)}
    shim_execs = []
    shim_roles = (_child_roles(root_role) | {root_role}) & _SHIM_SPAWN_ROLES
    if shim_roles:
        from tests import stand_shim

        shim_role, = shim_roles
        scenario = shim_role[-1]
        shim_path = str(stand_shim.shim_path(run_dir))
        fake_path = str(stand_shim.fake_path(run_dir))
        claude_commands = [stand_shim.command(scenario)]
        if scenario in HISTORY_SCENARIOS:
            claude_commands.append(stand_shim.history_start_command())

    def shim_transition(role: Role, line: str) -> Role | None:
        if not shim_roles or (command := _exec_command(line)) is None:
            return None
        path, argv = command
        for claude_command in claude_commands:
            if role == shim_role and path == shim_path and argv == claude_command:
                return ("path-shim",)
            if role == ("path-shim",) and path == sys.executable and argv == [
                sys.executable, "-I", "-m", "claude_swap.transparent",
                f"--cswap-shim=0:{Path(shim_path).parent}", *claude_command[1:]
            ]:
                return ("shim-python",)
            if role == ("shim-python",) and scenario not in SHIM_REFUSALS and (
                path == fake_path and len(argv) >= 3 and argv[:2] == [fake_path, "--settings"] and
                stand_shim.is_layer_path(run_dir, argv[2]) and argv[3:] == claude_command[1:]
            ):
                return ("shim-claude",)
        return None

    def visit(pid: int, role: Role, *, supervised_child: bool = False) -> None:
        subreaper = False
        split = False
        child_handoff = False
        for line in by_pid[pid][1 if pid == root else 0:]:
            syscall = _SYSCALL.match(line)
            if not syscall:
                continue
            call = syscall[1]
            if call in {"clone", "clone3", "fork", "vfork"}:
                result = _RESULT.search(line)
                successful = bool(result and result[1].isdigit() and parents.get(int(result[1])) == pid)
                supervisor_split = False
                if role == ("stand_mock", "client", "cli_positive") and "CLONE_THREAD" in line:
                    violations.append(f"pid {pid}: explicit supervisor fixture created a thread")
                if role in {("path-shim",), ("shim-python",), ("stand_mock", "client", "cli_positive")} and "CLONE_THREAD" not in line:
                    supervisor_split = bool(
                        role in {("shim-python",), ("stand_mock", "client", "cli_positive")} and subreaper and not split
                        and not supervised_child and successful and call in {"fork", "clone"}
                        and "CLONE_VM" not in line and "CLONE_VFORK" not in line
                    )
                    if not supervisor_split:
                        violations.append(f"pid {pid}: shim spawned a process without supervisor provenance")
                    split = True
                if "CLONE_NEW" in line or "CLONE_UNTRACED" in line:
                    violations.append(f"pid {pid}: unexpected process isolation flags in {call}")
                if successful:
                    visit(int(result[1]), role, supervised_child=supervisor_split)
            elif call == "prctl":
                if re.fullmatch(r"prctl\(PR_SET_CHILD_SUBREAPER, 1\)\s+= 0", line) and role in {("shim-python",), ("stand_mock", "client", "cli_positive")} and not split:
                    subreaper = True
            elif call in {"execve", "execveat"}:
                argv = _exec_argv(line) or []
                if role == root_role and tuple(argv) in child_commands:
                    new_role = child_commands[tuple(argv)]
                elif role in TLS_SERVER_ROLES and argv and argv[0] == openssl:
                    new_role = ("openssl",)
                elif transition := shim_transition(role, line):
                    new_role = transition
                    if new_role == ("shim-claude",) and (not supervised_child or split):
                        violations.append(f"pid {pid}: pinned handoff did not come from the supervisor child")
                    if line.endswith(" = 0"):
                        child_handoff = new_role == ("shim-claude",)
                        shim_execs.append(new_role[0])
                else:
                    violations.append(f"pid {pid}: non-allowlisted {call}")
                    new_role = ()
                if line.endswith(" = 0"):
                    role = new_role
            elif call in {"unshare", "setns", "io_uring_setup"}:
                violations.append(f"pid {pid}: unexpected {call}")
            elif call in {"connect", "sendto", "sendmsg", "sendmmsg"}:
                if role in {("path-shim",), ("shim-python",)}:
                    violations.append(f"pid {pid}: network before pinned handoff")
                if role == ("stand_mock", "client", "cli_positive") and not supervised_child:
                    violations.append(f"pid {pid}: network outside supervisor child")
                result = _RESULT.search(line)
                if not result or "<unfinished ...>" in line:
                    raise StandError(f"cannot audit {call} for pid {pid}")
                for target, source in _targets(call, line):
                    permitted = bool(target and target[1] != 53 and (
                        target in allowed.get(role, ()) or (
                            source in listeners.get(role, ())
                            and ipaddress.ip_address(target[0]).is_loopback
                        )
                    ))
                    attempt = Attempt(pid, call, role, target, result[1], permitted)
                    attempts.append(attempt)
                    if not permitted:
                        label = "DNS" if attempt.dns else "unapproved destination"
                        violations.append(
                            f"pid {pid} {role!r} {call}: {label} {target!r} ({attempt.result})"
                        )

        if supervised_child and role == ("shim-python",) and not child_handoff:
            violations.append(f"pid {pid}: supervisor child did not perform the pinned handoff")

    visit(root, root_role)
    return tuple(attempts), tuple(violations), tuple(shim_execs)


class LinuxStand:
    """Run only fixed stand workers in fresh, traceable Linux namespaces."""

    def __init__(self, tmp_path: Path) -> None:
        self.tmp_path = tmp_path.resolve()

    def run(
        self, module: str, *args: str, allowed: set[Target] | None = None,
        children: dict[Role, set[Target]] | None = None,
        listeners: dict[Role, set[Target]] | None = None,
        hosts_text: str = HOSTS,
    ) -> StandRun:
        """Launch one scenario; report attempts for the root role and each child.

        `allowed` and `children` allow outgoing connections by role. `listeners`
        separately allows replies on accepted loopback TCP connections.
        """
        if sys.platform != "linux" or os.environ.get(OPT_IN) != "1":
            raise StandError(f"set {OPT_IN}=1 on Linux to run the network stand")
        role = (module, *args)
        if role not in ROOT_ROLES:
            raise StandError("stand entry point is not allowlisted")
        policy = {role: allowed or set(), **(children or {})}
        inbound = listeners or {}
        roles = {role} | _child_roles(role)
        if roles & _SHIM_SPAWN_ROLES:
            roles.add(("shim-claude",))
        if (policy.keys() | inbound.keys()) - roles:
            raise StandError("stand policy specified an unknown process role")
        for endpoints in (*policy.values(), *inbound.values()):
            for addr, port in endpoints:
                if not ipaddress.ip_address(addr).is_loopback or not 0 < port < 65536 or port == 53:
                    raise StandError("allowed stand endpoints must be loopback and must not be DNS")
        run_dir = Path(mkdtemp(prefix="stand-", dir=self.tmp_path))
        for name in ("home", "data", "config", "cache", "state", "tmp", "bin", "empty"):
            (run_dir / name).mkdir(mode=0o700)
        resolver_files = {"hosts": hosts_text, "resolv.conf": RESOLV_CONF, "nsswitch.conf": NSSWITCH}
        for name, text in resolver_files.items():
            (run_dir / name).write_text(text)
        destinations = json.dumps([(name, sorted(dest)) for name, dest in policy.items()])
        env = {
            OPT_IN: "1", "CLAUDE_SWAP_TEST_MODE": "1",
            "PATH": str(run_dir / "bin"), "LANG": "C.UTF-8",
            "HOME": str(run_dir / "home"), "USERPROFILE": str(run_dir / "home"),
            "XDG_DATA_HOME": str(run_dir / "data"), "XDG_CONFIG_HOME": str(run_dir / "config"),
            "XDG_CACHE_HOME": str(run_dir / "cache"), "XDG_STATE_HOME": str(run_dir / "state"),
            "TMPDIR": str(run_dir / "tmp"), "OPENSSL_CONF": "/dev/null",
            "CSWAP_STAND_ROOT": str(run_dir),
            "CSWAP_STAND_DESTINATIONS": destinations,
            "CSWAP_STAND_OUTER_NET": _namespace("net"), "CSWAP_STAND_OUTER_MNT": _namespace("mnt"),
        }
        argv = [
            _tool("unshare"), "-n", "-m", "--propagation", "private", "--",
            sys.executable, "-Es", "-m", "tests.stand_linux", "enter", module, *args,
        ]
        timeout = TIMEOUT
        if (identity := os.environ.get("CSWAP_STAND_RUN_AS")) or os.environ.get("CSWAP_STAND_SUDO"):
            if (
                os.environ.get("CSWAP_STAND_SUDO") != "1"
                or os.geteuid() == 0 or os.getegid() == 0
                or identity != f"{os.geteuid()}:{os.getegid()}"
            ):
                raise StandError("sudo stand requires CSWAP_STAND_RUN_AS set to the caller's non-root uid:gid")
            env["CSWAP_STAND_RUN_AS"] = identity
            # The caller cannot signal root setup if it stalls. Put the same
            # timeout inside sudo and give it time to terminate its own group.
            argv = [
                _tool("sudo"), "-n", "--", _tool("env"), "-i",
                *(f"{key}={value}" for key, value in env.items()),
                _tool("timeout"), "--signal=KILL", str(TIMEOUT), *argv,
            ]
            timeout += 5
        with subprocess.Popen(
            argv, cwd=PROJECT, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, start_new_session=True,
        ) as process:
            try:
                stdout, stderr = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired as exc:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate()
                raise StandError("network stand timed out") from exc
        try:
            net, mnt = (run_dir / "isolated").read_text().splitlines()
            traced_rc = int((run_dir / "trace-completed").read_text())
        except (OSError, ValueError) as exc:
            raise StandError(f"stand setup did not complete: {stderr}") from exc
        if net == env["CSWAP_STAND_OUTER_NET"] or mnt == env["CSWAP_STAND_OUTER_MNT"]:
            raise StandError("stand did not confirm fresh namespaces")
        if traced_rc != process.returncode or traced_rc < 0 or "strace:" in stderr:
            raise StandError(f"strace did not complete normally: {stderr}")
        attempts, violations, shim_execs = _audit(run_dir, role, policy, inbound)
        return StandRun(stdout, stderr, process.returncode, attempts, violations, shim_execs)


if __name__ == "__main__":
    stage, module, *args = sys.argv[1:]
    if stage == "enter":
        raise SystemExit(_enter(module, args))
    if stage == "trace":
        raise SystemExit(_trace(module, args))
    if stage == "worker":
        _worker(module, args)
    else:
        raise StandError("not a stand entry point")
