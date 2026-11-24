"""Exercise normal CLI behavior in a child without reaching live services."""

import os
import runpy
import sys

from claude_swap import macos_keychain, test_mode, update_check


def install():
    """Use only for CLI unit tests, never for test-mode integration tests."""
    assert os.environ.get(test_mode.MODE) == "1"

    def no_network(event, args):
        if event.startswith("socket."):
            raise AssertionError(f"CLI unit child attempted {event}")

    sys.addaudithook(no_network)
    test_mode.active = lambda: False
    update_check.check_for_update = lambda _: None
    macos_keychain.get_password = lambda *args, **kwargs: None
    macos_keychain.item_exists = lambda *args, **kwargs: False

    def no_keychain_write(*args, **kwargs):
        raise AssertionError("CLI unit child attempted a Keychain write")

    macos_keychain.set_password = no_keychain_write
    macos_keychain.delete_password = no_keychain_write


if __name__ == "__main__":
    install()
    runpy.run_module("claude_swap", run_name="__main__", alter_sys=True)
