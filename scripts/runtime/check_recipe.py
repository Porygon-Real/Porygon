#!/usr/bin/env python3
"""Check one or more recipes without collecting a dataset run.

Starts the image exactly as run_image.py does (internal network, optional
sidecar, healthcheck, loopback relay), then exercises the pieces a run depends
on: the load driver through the relay, the RT-HN-ADMIN command, the RT-HN-LOGS
command, the /bin/sh used by every abnormal action, and a container restart.
Also records which shell and network tools the image actually ships.

Nothing is written to datasets/: set PORYGON_RT_RAW_ROOT to a scratch directory
(the default here) so the probe's own files stay out of the dataset.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

DEFAULT_RAW = Path(os.environ.get("PORYGON_RT_CHECK_ROOT")
                   or Path(__file__).resolve().parents[2] / "artifacts" / "runtime-recipe-checks")
os.environ.setdefault("PORYGON_RT_RAW_ROOT", str(DEFAULT_RAW))
os.environ.setdefault("PORYGON_RT_RUN_LOG", str(DEFAULT_RAW / "run-log.jsonl"))

sys.path.insert(0, str(Path(__file__).resolve().parent))
from drivers import ping  # noqa: E402
from recipes import RECIPES  # noqa: E402
from rt_common import docker, now  # noqa: E402
from run_image import ImageFailed, Run  # noqa: E402
from scenarios import _exec  # noqa: E402

TOOLS = "sh bash curl wget nc ps id cat python3 uname chmod cp"


def check(key: str) -> dict[str, object]:
    recipe = RECIPES[key]
    run = Run(key, 1, 1, batch="recipe-check")
    run_id = f"{key}-check-{now().strftime('%Y%m%dT%H%M%SZ')}"
    out: dict[str, object] = {"image_key": key, "tag": recipe["tag"], "started_at": now().isoformat()}
    try:
        record = run.start(run_id)
        out["start"] = "ok"
        out["user"] = record.get("user")
        out["host_port"] = run.port
        out["driver_ping"] = ping(recipe, run.port)
        inventory = _exec(run.name, ["/bin/sh", "-c",
                                     f'for t in {TOOLS}; do printf "%s=%s\\n" "$t" "$(command -v $t || echo -)"; done'])
        out["tools"] = dict(line.split("=", 1) for line in inventory["stdout_tail"].splitlines() if "=" in line)
        out["sh_available"] = inventory["returncode"] == 0
        admin = _exec(run.name, recipe["admin"], user=recipe.get("admin_user"))
        out["admin"] = {"returncode": admin["returncode"], "stdout_tail": admin["stdout_tail"][-200:],
                        "stderr_tail": admin["stderr_tail"][-300:]}
        if recipe.get("log") == "docker_logs":
            logs = docker("logs", "--tail", "5", run.name)
            out["log"] = {"mode": "docker_logs", "returncode": logs.returncode}
        else:
            tail = _exec(run.name, ["tail", "-n", "5", recipe["log"]])
            out["log"] = {"mode": recipe["log"], "returncode": tail["returncode"],
                          "stderr_tail": tail["stderr_tail"][-200:]}
        maint = _exec(run.name, ["/bin/sh", "-c", "id; uname -a; ps"])
        out["maint_shell_returncode"] = maint["returncode"]
        root = _exec(run.name, ["/bin/sh", "-c", "id"], user="0")
        out["root_exec_returncode"] = root["returncode"]
        restart = run.restart()
        out["restart"] = {"returncode": restart.get("returncode"), "error": restart.get("error", "")[:300],
                          "relay_restarted": restart.get("relay_restarted", False)}
        out["driver_ping_after_restart"] = ping(recipe, run.port)
    except ImageFailed as exc:
        out["start"] = "failed"
        out["error"] = str(exc)[:1500]
    except Exception as exc:  # noqa: BLE001 - a probe failure is reported, never hidden
        out["start"] = "error"
        out["error"] = repr(exc)[:1500]
    finally:
        out["cleanup"] = run.cleanup(run_id)
    problems = []
    if out.get("start") != "ok":
        problems.append(f"start {out.get('start')}: {str(out.get('error'))[:300]}")
    else:
        if not out.get("driver_ping"):
            problems.append("the load driver could not reach the service through the relay")
        if not out.get("driver_ping_after_restart"):
            problems.append("the load driver could not reach the service after a restart")
        if (out.get("admin") or {}).get("returncode") != 0:
            problems.append(f"admin command failed: {json.dumps(out.get('admin'))[:400]}")
        if (out.get("log") or {}).get("returncode") != 0:
            problems.append(f"log command failed: {json.dumps(out.get('log'))[:300]}")
        if not out.get("sh_available"):
            problems.append("/bin/sh is not available, so the abnormal actions cannot run")
        if (out.get("restart") or {}).get("error"):
            problems.append(f"restart problem: {(out.get('restart') or {}).get('error')}")
    out["problems"] = problems
    out["ok"] = not problems
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("images", nargs="+", choices=sorted(RECIPES) + ["ALL"])
    parser.add_argument("--out", default=str(DEFAULT_RAW / "recipe-checks.json"))
    args = parser.parse_args()
    results = []
    for key in args.images:
        print(f"--- {key}", flush=True)
        result = check(key)
        results.append(result)
        print(json.dumps({k: v for k, v in result.items() if k not in ("tools", "cleanup")},
                         default=str)[:1200], flush=True)
        print(f"    tools: {json.dumps(result.get('tools', {}))}"[:600], flush=True)
        time.sleep(2)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    previous = json.loads(out_path.read_text(encoding="utf-8")) if out_path.is_file() else []
    merged = {r["image_key"]: r for r in previous if isinstance(r, dict)}
    merged.update({r["image_key"]: r for r in results})
    out_path.write_text(json.dumps(list(merged.values()), indent=2, default=str) + "\n", encoding="utf-8")
    bad = [r["image_key"] for r in results if not r["ok"]]
    print(f"\n{len(results)} checked; problems in {bad}" if bad else f"\n{len(results)} checked; all ok")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
