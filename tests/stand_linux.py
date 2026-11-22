"""Linux-only, opt-in launcher and independent syscall audit for the test stand."""

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
MOCK_SCENARIOS = ("positive", "direct", "denied_connect")
ROOT_ROLES = {
    *(("stand_mock", scenario) for scenario in MOCK_SCENARIOS),
    *(("stand_linux_control", name) for name in ("normal", "dns", "failed")),
}


def _child_roles(role: Role) -> set[Role]:
    if role == ("stand_linux_control", "dns"):
        return {("stand_linux_control", "query")}
    if len(role) == 2 and role[0] == "stand_mock" and role[1] in MOCK_SCENARIOS:
        return {("stand_mock", "serve"), ("stand_mock", "client", role[1])}
    return set()


WORKER_ROLES = ROOT_ROLES.union(*(_child_roles(role) for role in ROOT_ROLES))


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
    (run_dir / "isolated").write_text(f"{_namespace('net')}\n{_namespace('mnt')}\n")
    require_isolation()
    result = subprocess.run([
        _tool("strace"), "-ff", "--kill-on-exit", "-yy", "-s", "256",
        "-o", str(run_dir / "trace"),
        "-e", "trace=%network,%process,io_uring_setup,unshare,setns",
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
    openssl = openssl_path() if role == ("stand_mock", "serve") else None
    destinations = next(
        ({tuple(target) for target in targets} for name, targets in
         json.loads(os.environ["CSWAP_STAND_DESTINATIONS"]) if tuple(name) == role),
        set(),
    )

    def restrict_worker(event: str, values: tuple) -> None:
        # Mock workers get a preventive Python gate as well as the syscall
        # detector. The standalone controls deliberately exercise strace alone.
        if module == "stand_mock" and event == "socket.connect":
            _, address = values
            if not isinstance(address, tuple) or address[:2] not in destinations:
                raise StandError(f"stand connect destination not allowed for {role!r}")
        if event == "subprocess.Popen":
            executable, argv, _cwd, _env = values
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
    runpy.run_module(f"tests.{module}", run_name="__main__")


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


def _exec_argv(line: str) -> list[str] | None:
    match = _EXEC.match(line)
    if match:
        try:
            argv = json.loads(match[2])
            if argv and argv[0] == match[1]:
                return argv
        except ValueError:
            pass
    return None


def _audit(
    run_dir: Path, root_role: Role, allowed: dict[Role, set[Target]],
    listeners: dict[Role, set[Target]],
) -> tuple[tuple[Attempt, ...], tuple[str, ...]]:
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

    def visit(pid: int, role: Role) -> None:
        for line in by_pid[pid][1 if pid == root else 0:]:
            syscall = _SYSCALL.match(line)
            if not syscall:
                continue
            call = syscall[1]
            if call in {"clone", "clone3", "fork", "vfork"}:
                if "CLONE_NEW" in line or "CLONE_UNTRACED" in line:
                    violations.append(f"pid {pid}: unexpected process isolation flags in {call}")
                result = _RESULT.search(line)
                if result and result[1].isdigit() and parents.get(int(result[1])) == pid:
                    visit(int(result[1]), role)
            elif call in {"execve", "execveat"}:
                argv = _exec_argv(line) or []
                if role == root_role and tuple(argv) in child_commands:
                    new_role = child_commands[tuple(argv)]
                elif role == ("stand_mock", "serve") and argv and argv[0] == openssl:
                    new_role = ("openssl",)
                else:
                    violations.append(f"pid {pid}: non-allowlisted {call}")
                    new_role = ()
                if line.endswith(" = 0"):
                    role = new_role
            elif call in {"unshare", "setns", "io_uring_setup"}:
                violations.append(f"pid {pid}: unexpected {call}")
            elif call in {"connect", "sendto", "sendmsg", "sendmmsg"}:
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

    visit(root, root_role)
    return tuple(attempts), tuple(violations)


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
        if (policy.keys() | inbound.keys()) - ({role} | _child_roles(role)):
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
        with subprocess.Popen(
            argv, cwd=PROJECT, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, start_new_session=True,
        ) as process:
            try:
                stdout, stderr = process.communicate(timeout=TIMEOUT)
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
        attempts, violations = _audit(run_dir, role, policy, inbound)
        return StandRun(stdout, stderr, process.returncode, attempts, violations)


if __name__ == "__main__":
    stage, module, *args = sys.argv[1:]
    if stage == "enter":
        raise SystemExit(_enter(module, args))
    if stage == "worker":
        _worker(module, args)
    else:
        raise StandError("not a stand entry point")
