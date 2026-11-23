"""Report the portable stand's startup checks without printing child output."""

import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory

from tests.stand_audit import StandAudit


_ROOT = """import subprocess
import sys
print("root body reached", flush=True)
sys.exit(subprocess.call([sys.executable, "-I", sys.argv[1]]))
"""
_DESCENDANT = 'print("descendant body reached")\n'


def probe(tmp_path):
    stand = StandAudit(tmp_path)
    root = stand.root / "root.py"
    descendant = stand.root / "descendant.py"
    root.write_text(_ROOT, encoding="utf-8")
    descendant.write_text(_DESCENDANT, encoding="utf-8")
    stand.allow(descendant)
    result = stand.run(root, str(descendant), check_audit=False)
    records = stand.records()
    started = [r["stage"] for r in records if r["kind"] == "startup"]
    bodies_reached = [f"{stage} body reached" for stage in started]
    if result.stdout.splitlines() != bodies_reached:
        raise AssertionError("portable stand probe did not reach expected script bodies")
    blocked = [r for r in records if r["kind"] == "blocked"]
    if not blocked:
        stand.assert_clean()
        if result.returncode != 0 or started != ["root", "descendant"]:
            raise AssertionError("unexpected successful startup probe marker sequence")
        return {"started": started, "exit": 0}
    if result.returncode != 125 or len(blocked) != 1 or blocked[0]["event"] != "startup":
        raise AssertionError("portable stand probe did not record a startup refusal")
    refusal = blocked[0]
    if (started, refusal["stage"]) not in (([], "root"), (["root"], "descendant")):
        raise AssertionError("unexpected refused startup probe marker sequence")
    details = {key: refusal[key] for key in ("stage", "reason", "environment") if key in refusal}
    return {"started": started, "exit": 125, "refusal": details}


def main():
    with TemporaryDirectory(prefix="cswap-audit-", dir=os.environ.get("RUNNER_TEMP")) as tmp:
        print(json.dumps(probe(Path(tmp).resolve()), sort_keys=True))


if __name__ == "__main__":
    main()
