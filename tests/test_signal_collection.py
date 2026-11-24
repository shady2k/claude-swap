"""Linux signal modules must import on hosts without POSIX signal constants."""
import builtins
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.mark.parametrize("filename", ["test_publication_refusal_signals.py", "test_spawn_signals.py"])
def test_signal_parameters_collect_without_posix_constants(filename):
    original_import = builtins.__import__
    def import_without_posix_signals(name, *args, **kwargs):
        if name == "signal":
            return SimpleNamespace(SIGINT=2, SIGTERM=15)
        return original_import(name, *args, **kwargs)

    source = Path(__file__).with_name(filename)
    namespace = {"__builtins__": {**vars(builtins), "__import__": import_without_posix_signals},
                 "__file__": str(source), "__name__": "signal_collection_control"}
    exec(compile(source.read_text(), str(source), "exec"), namespace)
