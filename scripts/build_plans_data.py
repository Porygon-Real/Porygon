#!/usr/bin/env python3
"""Build structured plans-data.json from plans/ directory for dashboard UI."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PLANS_DIR = ROOT / "plans"
OUTPUT_FILE = ROOT / "dashboard" / "plans-data.json"


def compute_sha256(path: Path) -> str | None:
    if not path.is_file():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_plan_markdown(path: Path) -> dict[str, Any]:
    content = path.read_text(encoding="utf-8")
    title_m = re.search(r"^#\s+(.+)$", content, re.MULTILINE)
    title = title_m.group(1).strip() if title_m else path.stem

    prio_m = re.search(r"-\s*Priority:\s*([^\n]+)", content)
    effort_m = re.search(r"-\s*Effort:\s*([^\n]+)", content)
    risk_m = re.search(r"-\s*Risk:\s*([^\n]+)", content)
    deps_m = re.search(r"-\s*Depends on:\s*([^\n]+)", content)
    cat_m = re.search(r"-\s*Category:\s*([^\n]+)", content)
    status_m = re.search(r"(?:-\s*Status:|Status:)\s*([^\n]+)", content)

    # Why this matters section
    why_m = re.search(r"##\s+Why this matters\s*\n\n(.*?)(?=\n##|\Z)", content, re.DOTALL)
    summary = why_m.group(1).strip() if why_m else ""
    if not summary:
        # Fallback to objective or first paragraph
        obj_m = re.search(r"##\s+Objective[^\n]*\s*\n\n(.*?)(?=\n##|\Z)", content, re.DOTALL)
        summary = obj_m.group(1).strip() if obj_m else ""

    # Done criteria / Verification / Acceptance
    done_m = re.search(r"##\s+(?:Done criteria|Verification|Local acceptance[^\n]*)\s*\n\n(.*?)(?=\n##|\Z)", content, re.DOTALL)
    done_criteria = done_m.group(1).strip() if done_m else ""

    # Extract mentioned file coordinates like `path/to/file.py:123`
    coords = re.findall(r"`([a-zA-Z0-9_\-\./]+\.[a-zA-Z0-9]+(?::\d+(?:–\d+)?)?)`", content)
    unique_coords = []
    seen = set()
    for c in coords:
        if "/" in c and c not in seen:
            seen.add(c)
            unique_coords.append(c)

    # Simplified status category
    raw_status = status_m.group(1).strip() if status_m else "IN PROGRESS"
    status_upper = raw_status.upper()
    if "DONE" in status_upper or "ACCEPTED" in status_upper:
        status_category = "DONE" if "DONE" in status_upper else "LOCAL ACCEPTED"
    elif "EXECUTING" in status_upper or "IN PROGRESS" in status_upper:
        status_category = "IN PROGRESS"
    elif "TODO" in status_upper:
        status_category = "TODO"
    else:
        status_category = "IN PROGRESS"

    plan_id_m = re.match(r"^(\d+)", path.name)
    plan_id = plan_id_m.group(1) if plan_id_m else path.stem

    return {
        "id": plan_id,
        "filename": path.name,
        "title": title,
        "priority": prio_m.group(1).strip() if prio_m else "P1",
        "effort": effort_m.group(1).strip() if effort_m else "2-4 weeks",
        "risk": risk_m.group(1).strip() if risk_m else "MED",
        "category": cat_m.group(1).strip() if cat_m else "architecture / security",
        "depends_on": deps_m.group(1).strip() if deps_m else "None",
        "status": raw_status,
        "status_category": status_category,
        "summary": summary,
        "done_criteria": done_criteria,
        "coordinates": unique_coords[:12],
        "content": content,
    }


def parse_review_markdown(path: Path) -> dict[str, Any]:
    content = path.read_text(encoding="utf-8")
    title_m = re.search(r"^#\s+(.+)$", content, re.MULTILINE)
    title = title_m.group(1).strip() if title_m else path.stem
    first_para = ""
    paras = [p.strip() for p in content.split("\n\n") if p.strip() and not p.startswith("#")]
    if paras:
        first_para = paras[0]

    return {
        "id": path.stem,
        "filename": path.name,
        "title": title,
        "summary": first_para,
        "content": content,
    }


def parse_vetted_findings(readme_path: Path) -> list[dict[str, Any]]:
    if not readme_path.exists():
        return []
    content = readme_path.read_text(encoding="utf-8")
    # Search table under "## Vetted findings"
    table_m = re.search(r"##\s+Vetted findings[^\n]*\n.*?\n\|([^\n]+)\|\n\|[-|\s]+\|\n(.*?)(?=\n\n|\n##|\Z)", content, re.DOTALL)
    if not table_m:
        return []

    rows = []
    lines = table_m.group(2).strip().splitlines()
    for line in lines:
        line = line.strip()
        if not line.startswith("|") or not line.endswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) >= 9:
            rows.append({
                "id": cells[0],
                "finding": cells[1],
                "category": cells[2],
                "impact": cells[3],
                "effort": cells[4],
                "risk": cells[5],
                "confidence": cells[6],
                "evidence": cells[7].replace("`", ""),
                "plan": cells[8],
            })
    return rows


def build_plans_data() -> dict[str, Any]:
    plans = []
    for p in sorted(PLANS_DIR.glob("00*.md")):
        plans.append(parse_plan_markdown(p))

    reviews = []
    for r in sorted(PLANS_DIR.glob("*review*.md")):
        reviews.append(parse_review_markdown(r))

    readme_path = PLANS_DIR / "README.md"
    findings = parse_vetted_findings(readme_path)

    # Evidence index check
    evidence_index_path = PLANS_DIR / "evidence-index.json"
    evidence_status = []
    evidence_meta = {}
    if evidence_index_path.is_file():
        evidence_meta = json.loads(evidence_index_path.read_text(encoding="utf-8"))
        for rel_path, meta in evidence_meta.get("files", {}).items():
            full_path = ROOT / rel_path
            current_hash = compute_sha256(full_path)
            expected_hash = meta.get("sha256", "")
            if current_hash is None:
                status = "MISSING"
            elif current_hash == expected_hash:
                status = "MATCH"
            else:
                status = "DRIFTED"

            evidence_status.append({
                "path": rel_path,
                "expected_sha256": expected_hash,
                "current_sha256": current_hash or "",
                "status": status,
                "plans": meta.get("plans", []),
            })

    # Execution baseline
    baseline_path = PLANS_DIR / "execution-baseline.json"
    baseline_data = {}
    if baseline_path.is_file():
        baseline_data = json.loads(baseline_path.read_text(encoding="utf-8"))

    stats = {
        "total_plans": len(plans),
        "done_plans": sum(1 for p in plans if p["status_category"] in ("DONE", "LOCAL ACCEPTED")),
        "in_progress_plans": sum(1 for p in plans if p["status_category"] == "IN PROGRESS"),
        "total_findings": len(findings),
        "total_tracked_evidence_files": len(evidence_status),
        "matching_evidence_files": sum(1 for e in evidence_status if e["status"] == "MATCH"),
        "drifted_evidence_files": sum(1 for e in evidence_status if e["status"] == "DRIFTED"),
        "planned_at_commit": evidence_meta.get("planned_at_commit", "b04aaea"),
    }

    result = {
        "stats": stats,
        "plans": plans,
        "reviews": reviews,
        "findings": findings,
        "evidence": evidence_status,
        "evidence_meta": evidence_meta,
        "baseline_summary": {
            "root": baseline_data.get("root", ""),
            "worktree": baseline_data.get("worktree", ""),
            "tracked_file_count": len(baseline_data.get("files", {})),
        },
    }
    return result


def main() -> None:
    data = build_plans_data()
    OUTPUT_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"[+] Wrote plans data to {OUTPUT_FILE}")
    print(f"    Total plans: {data['stats']['total_plans']}")
    print(f"    Done/Accepted: {data['stats']['done_plans']}")
    print(f"    In Progress: {data['stats']['in_progress_plans']}")
    print(f"    Vetted findings: {data['stats']['total_findings']}")
    print(f"    Tracked evidence files: {data['stats']['total_tracked_evidence_files']}")


if __name__ == "__main__":
    main()
