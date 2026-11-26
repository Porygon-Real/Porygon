"""Read-only drift check for the source evidence used by the pathway plans."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', choices=['all', '001', '002', '003', '004', '005'], default='all')
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    evidence = json.loads((root / 'plans/evidence-index.json').read_text())
    changed = []
    for name, expected in evidence['files'].items():
        if args.plan != 'all' and args.plan not in expected['plans']:
            continue
        path = root / name
        actual = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
        if actual != expected['sha256']:
            changed.append(name)
    if changed:
        print('DRIFT: re-read these files and reconcile the plan before executing:')
        print('\n'.join(changed))
        return 2
    print('PASS: source evidence matches the recorded working-tree snapshot')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
