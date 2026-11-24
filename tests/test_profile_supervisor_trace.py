"""Independent syscall controls for the one explicit-session supervisor split."""
import json
import pytest
from tests import stand_linux as stand

ROLE = ("stand_mock", "client", "cli_positive")
PROXY = ("127.0.0.1", 18080)


def trace_tree(tmp_path, variant):
    def connect(target):
        host, port = target
        return f'connect(3, {{sa_family=AF_INET, sin_port=htons({port}), sin_addr=inet_addr("{host}")}}, 16) = 0'
    parent = [f'execve("{stand.worker_argv(*ROLE)[0]}", {json.dumps(stand.worker_argv(*ROLE))}, 0x0) = 0']
    if variant != "no-prctl":
        parent.append('prctl(PR_SET_CHILD_SUBREAPER, 1) = 0')
    parent.append('clone(child_stack=NULL, flags=SIGCHLD) = 102')
    child = []
    if variant == "child-fork":
        child += ['prctl(PR_SET_CHILD_SUBREAPER, 1) = 0', 'clone(child_stack=NULL, flags=SIGCHLD) = 103']
    elif variant == "second-fork":
        parent.append('clone(child_stack=NULL, flags=SIGCHLD) = 103')
    elif variant == "thread-fork":
        parent.append('clone(child_stack=NULL, flags=CLONE_VM|CLONE_THREAD) = 103')
    elif variant == "parent-network":
        parent.append(connect(PROXY))
    elif variant == "offdest":
        child.append(connect(("127.0.0.1", 18443)))
    elif variant == "dns":
        child.append(connect(("127.0.0.53", 53)))
    else:
        child.append(connect(PROXY))
    ending = ['exit_group(0) = ?', '+++ exited with 0 +++']
    for pid, lines in ((101, parent), (102, child)):
        (tmp_path/f"trace.{pid}").write_text("\n".join(lines+ending)+"\n")
    if variant in ("child-fork", "second-fork", "thread-fork"):
        (tmp_path/"trace.103").write_text("\n".join(ending)+"\n")
    return stand._audit(tmp_path, ROLE, {ROLE:{PROXY}}, {})


def test_explicit_supervisor_child_inherits_only_proxy_destination(tmp_path):
    attempts, violations, _ = trace_tree(tmp_path, "positive")
    assert not violations
    assert len(attempts) == 1 and attempts[0].pid == 102
    assert attempts[0].role == ROLE and attempts[0].permitted


@pytest.mark.parametrize("variant", ["no-prctl", "second-fork", "child-fork", "thread-fork", "parent-network", "offdest", "dns"])
def test_explicit_supervisor_trace_rejects_extra_processes_and_network(tmp_path, variant):
    _, violations, _ = trace_tree(tmp_path, variant)
    assert violations, variant
