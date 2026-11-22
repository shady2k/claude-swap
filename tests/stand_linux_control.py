"""Loopback-only positive/no-DNS and isolated negative controls for strace."""

from __future__ import annotations

import errno
import socket
import subprocess
import sys

from tests.stand_linux import DNS_SINK, require_isolation, worker_argv


LOCAL = ("127.0.0.1", 19279)
FAILED_TARGET = ("192.0.2.42", 443)  # TEST-NET-1; unreachable in the stand.
QUERY = "stand-dns-probe.invalid."


def _normal() -> None:
    with socket.create_server(LOCAL) as listener:
        with socket.create_connection(LOCAL) as client, listener.accept()[0] as server:
            client.sendall(b"ping")
            assert server.recv(4) == b"ping"
            server.sendall(b"pong")
            assert client.recv(4) == b"pong"


def _dns() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sink:
        sink.bind(DNS_SINK)
        sink.settimeout(3)
        with subprocess.Popen(worker_argv("stand_linux_control", "query")) as query:
            # Intentionally never respond: the child must observe a timeout.
            payload, source = sink.recvfrom(512)
            assert source[0].startswith("127.")
            assert b"\x0fstand-dns-probe\x07invalid\x00" in payload.lower()
            assert query.wait(timeout=5) == 0


def _query() -> None:
    try:
        socket.getaddrinfo(QUERY, None, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        if exc.errno == socket.EAI_AGAIN:
            return
        raise
    raise AssertionError("drop-only DNS sink must not resolve the reserved name")


def _failed() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp:
        assert tcp.connect_ex(FAILED_TARGET) == errno.ENETUNREACH
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        for send in (udp.sendto, lambda data, dest: udp.sendmsg([data], [], 0, dest)):
            try:
                send(b"stand-negative-control", FAILED_TARGET)
            except OSError as exc:
                assert exc.errno == errno.ENETUNREACH
            else:
                raise AssertionError("the stand unexpectedly routed a datagram")


if __name__ == "__main__":
    require_isolation()
    {"normal": _normal, "dns": _dns, "query": _query, "failed": _failed}[sys.argv[1]]()
