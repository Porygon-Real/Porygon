"""The fixed 30-window test schedule and the real actions run in each window.

Ground truth comes from the schedule, fixed before the test phase starts:
plain normal and hard negatives are "normal", the 12 attacker-shaped actions
are "abnormal". Abnormal actions are harmless reproductions of attacker
behaviour inside a disposable, internet-less container: no exploit, no malware.
"""
from __future__ import annotations

import random
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from experiments.real import ATTACK_LIKE_SCENARIOS, COMMAND_TEMPLATE  # noqa: E402

from rt_common import docker, now, iso  # noqa: E402

CANARY = "porygon-canary"

# (scenario_id, name, kind, ground_truth)
NORMAL = [("RT-NORMAL", "plain normal load", "normal", "normal")] * 11 + [
    ("RT-NORMAL-RESTART", "plain normal load with a container restart", "normal", "normal")]
HARD_NEGATIVES = [
    ("RT-HN-ADMIN", "admin status command", "hard_negative", "normal"),
    ("RT-HN-ADMIN", "admin status command", "hard_negative", "normal"),
    ("RT-HN-MAINT-SHELL", "maintenance shell (id; uname -a; ps)", "hard_negative", "normal"),
    ("RT-HN-MAINT-SHELL", "maintenance shell (id; uname -a; ps)", "hard_negative", "normal"),
    ("RT-HN-LOGS", "log inspection", "hard_negative", "normal"),
    ("RT-HN-LOGS", "log inspection", "hard_negative", "normal"),
]
ABNORMAL = [
    ("RT-AB-SHELL-RECON", "shell and reconnaissance", "abnormal", "abnormal"),
    ("RT-AB-READ-SHADOW", "read /etc/shadow", "abnormal", "abnormal"),
    ("RT-AB-EGRESS", "wget/curl to TEST-NET 203.0.113.1", "abnormal", "abnormal"),
    ("RT-AB-NC-CONNECT", "nc connect to an unreachable internal address", "abnormal", "abnormal"),
    ("RT-AB-DROPPED-SCRIPT", "dropped script in /tmp (write, chmod +x, run)", "abnormal", "abnormal"),
    ("RT-AB-RENAMED-BINARY", "renamed binary run from /tmp (miner-shaped name)", "abnormal", "abnormal"),
    ("RT-AB-ROOT-EXEC", "docker exec -u 0 into the service", "abnormal", "abnormal"),
    ("SCN-LOG4SHELL-SIM", "Log4Shell-shaped process behaviour (no exploit)", "abnormal", "abnormal"),
    ("SCN-RUNC-ESCAPE-SIM", "runc-escape-shaped process behaviour (no exploit)", "abnormal", "abnormal"),
    ("SCN-FLOOD", "burst of 120 exec commands", "abnormal", "abnormal"),
    ("RT-AB-LOW-SLOW", "low-and-slow reconnaissance spread across the window", "abnormal", "abnormal"),
    ("RT-AB-PKG-INSTALL", "package-manager install attempt (fails offline)", "abnormal", "abnormal"),
]

SHELL_SCRIPTS: dict[str, str] = {
    "RT-AB-SHELL-RECON": "id; whoami; uname -a; cat /etc/passwd",
    "RT-AB-READ-SHADOW": "cat /etc/shadow",
    "RT-AB-EGRESS": ("if command -v wget >/dev/null 2>&1; then wget -q -T 5 -O- http://203.0.113.1/; "
                     "else curl -s -m 5 http://203.0.113.1/; fi"),
    "RT-AB-NC-CONNECT": "nc -w 3 10.255.255.1 4444 </dev/null",
    "RT-AB-DROPPED-SCRIPT": ("printf '#!/bin/sh\\nid\\nuname -a\\nls /\\n' > /tmp/.sys-update.sh; "
                             "chmod +x /tmp/.sys-update.sh; /tmp/.sys-update.sh"),
    "RT-AB-RENAMED-BINARY": ("cp \"$(command -v sleep)\" /tmp/kdevtmpfsi; chmod +x /tmp/kdevtmpfsi; /tmp/kdevtmpfsi 2"),
    "RT-AB-ROOT-EXEC": "id; ls -la /root; head -n 5 /proc/1/status",
    "RT-AB-PKG-INSTALL": ("if command -v apt-get >/dev/null 2>&1; then apt-get update -qq; apt-get install -y -qq nmap; "
                          "elif command -v apk >/dev/null 2>&1; then apk add --no-cache nmap; "
                          "elif command -v microdnf >/dev/null 2>&1; then microdnf install -y nmap; "
                          "elif command -v dnf >/dev/null 2>&1; then dnf install -y nmap; "
                          "else yum install -y nmap; fi"),
    "RT-HN-MAINT-SHELL": "id; uname -a; ps",
}
LOW_SLOW_STEPS = ["id", "uname -a", "cat /etc/passwd", "ls -la /root", "cat /proc/self/cgroup", "env"]

# Substrings that identify the action's own processes in Porygon's process events.
FALCO_PROBES: dict[str, list[str]] = {
    "RT-AB-SHELL-RECON": ["/etc/passwd"], "RT-AB-READ-SHADOW": ["/etc/shadow"], "RT-AB-EGRESS": ["203.0.113.1"],
    "RT-AB-NC-CONNECT": ["10.255.255.1"], "RT-AB-DROPPED-SCRIPT": [".sys-update.sh"],
    "RT-AB-RENAMED-BINARY": ["kdevtmpfsi"], "RT-AB-ROOT-EXEC": ["/proc/1/status"],
    "SCN-LOG4SHELL-SIM": [CANARY], "SCN-RUNC-ESCAPE-SIM": [CANARY], "SCN-FLOOD": [CANARY],
    "RT-AB-LOW-SLOW": ["/proc/self/cgroup", "/etc/passwd"], "RT-AB-PKG-INSTALL": ["nmap"],
    "RT-HN-MAINT-SHELL": ["uname -a"],
}


def build_schedule(seed: int) -> list[dict[str, Any]]:
    slots = NORMAL + HARD_NEGATIVES + ABNORMAL
    assert len(slots) == 30
    order = list(range(30))
    random.Random(seed).shuffle(order)
    return [{"window_index": i, "scenario_id": slots[j][0], "scenario_name": slots[j][1], "kind": slots[j][2],
             "ground_truth": slots[j][3]} for i, j in enumerate(order)]


def _exec(container: str, argv: list[str], *, user: str | None = None, timeout: int = 50) -> dict[str, Any]:
    args = ["exec"] + (["-u", user] if user else []) + [container] + argv
    started = time.monotonic()
    result = docker(*args, timeout=timeout)
    return {"argv": ["docker", *args], "returncode": result.returncode, "duration_s": round(time.monotonic() - started, 3),
            "stdout_tail": result.stdout[-400:], "stderr_tail": result.stderr[-400:]}


def run_action(window: dict[str, Any], container: str, recipe: dict[str, Any], run_id: str,
               deadline: float, restart_fn) -> dict[str, Any]:
    """Run the window's real action. Returns the commands and their return codes."""
    sid = window["scenario_id"]
    steps: list[dict[str, Any]] = []
    started = iso(now())
    if sid == "RT-NORMAL":
        pass
    elif sid == "RT-NORMAL-RESTART":
        steps.append(restart_fn())
    elif sid == "RT-HN-ADMIN":
        steps.append(_exec(container, recipe["admin"], user=recipe.get("admin_user")))
    elif sid == "RT-HN-LOGS":
        if recipe.get("log") == "docker_logs":
            result = docker("logs", "--tail", "50", container)
            steps.append({"argv": ["docker", "logs", "--tail", "50", container], "returncode": result.returncode,
                          "note": "image logs to stdout; inspected with docker logs (no process in the container)"})
        else:
            steps.append(_exec(container, ["tail", "-n", "20", recipe["log"]]))
    elif sid in SHELL_SCRIPTS:
        user = "0" if sid == "RT-AB-ROOT-EXEC" else None
        steps.append(_exec(container, ["/bin/sh", "-c", SHELL_SCRIPTS[sid]], user=user, timeout=55))
    elif sid in ATTACK_LIKE_SCENARIOS:
        template = ATTACK_LIKE_SCENARIOS[sid]["command_template"]
        for seq in range(1, 7):
            marker = f"{CANARY}--{run_id}--w{window['window_index']}--{seq}"
            steps.append(_exec(container, ["/bin/sh", "-c", template.format(canary=marker)], timeout=20))
            time.sleep(0.5)
    elif sid == "SCN-FLOOD":
        for seq in range(1, 121):
            if time.monotonic() > deadline:
                steps.append({"note": f"stopped at sequence {seq} to stay inside the window"})
                break
            marker = f"{CANARY}--{run_id}--w{window['window_index']}--{seq}"
            steps.append(_exec(container, ["/bin/sh", "-c", COMMAND_TEMPLATE.format(canary=marker)], timeout=15))
    elif sid == "RT-AB-LOW-SLOW":
        for step in LOW_SLOW_STEPS:
            steps.append(_exec(container, ["/bin/sh", "-c", step], timeout=15))
            if time.monotonic() + 8 > deadline:
                break
            time.sleep(7)
    else:
        raise ValueError(f"unknown scenario {sid}")
    codes = [s["returncode"] for s in steps if "returncode" in s]
    return {"action_started_at": started, "action_finished_at": iso(now()), "steps": steps,
            "returncode": None if not codes else (0 if all(c == 0 for c in codes) else max(codes, key=abs)),
            "returncodes": codes}


def describe_commands(window: dict[str, Any], recipe: dict[str, Any]) -> str:
    sid = window["scenario_id"]
    if sid == "RT-NORMAL":
        return ""
    if sid == "RT-NORMAL-RESTART":
        return "docker restart"
    if sid == "RT-HN-ADMIN":
        return " ".join(recipe["admin"])
    if sid == "RT-HN-LOGS":
        return "docker logs --tail 50" if recipe.get("log") == "docker_logs" else f"tail -n 20 {recipe['log']}"
    if sid in SHELL_SCRIPTS:
        return ("docker exec -u 0 " if sid == "RT-AB-ROOT-EXEC" else "") + SHELL_SCRIPTS[sid]
    if sid in ATTACK_LIKE_SCENARIOS:
        return "6x " + ATTACK_LIKE_SCENARIOS[sid]["command_template"]
    if sid == "SCN-FLOOD":
        return "120x " + COMMAND_TEMPLATE
    if sid == "RT-AB-LOW-SLOW":
        return " ; (7 s) ".join(LOW_SLOW_STEPS)
    return sid
