"""Bounded tracked-source secret-pattern gate; output coordinates, never values."""
from pathlib import Path
import re
import subprocess

ROOT=Path(__file__).resolve().parents[1]
PATTERNS=(re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
    re.compile(rb'\b(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,}|AKIA[A-Z0-9]{16})\b'))


def main():
    paths=subprocess.run(['git','ls-files','-z'],cwd=ROOT,capture_output=True,check=True).stdout.split(b'\0')
    findings=[]
    for raw in paths:
        if not raw:continue
        path=ROOT/raw.decode()
        if path.is_symlink() or not path.is_file() or path.stat().st_size>4*1024*1024:continue
        content=path.read_bytes()
        for pattern in PATTERNS:
            for match in pattern.finditer(content):
                findings.append({'file':str(path.relative_to(ROOT)),'line':content[:match.start()].count(b'\n')+1,'kind':'credential-pattern'})
    for finding in findings:print(f"{finding['file']}:{finding['line']}: {finding['kind']}")
    return int(bool(findings))


if __name__=='__main__':raise SystemExit(main())
