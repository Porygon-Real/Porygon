"""Resolve installed service dependency graphs to PyPI wheel hashes (no installs).

Run after deliberately updating/rebuilding the dependency graph. Review the diff;
this command does not establish that the selected versions are vulnerability-free.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
from urllib.request import urlopen

ROOT=Path(__file__).resolve().parents[1]
SERVICES=('backend','collector','telemetry','responder','scanner')


def wheel_hashes(name,version):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+',name+version):raise ValueError('Invalid package coordinate')
    with urlopen(f'https://pypi.org/pypi/{name}/{version}/json',timeout=30) as response:
        value=json.load(response)
    hashes=sorted({item['digests']['sha256'] for item in value['urls'] if item['packagetype']=='bdist_wheel' and not item.get('yanked')})
    if not hashes:raise ValueError(f'No non-yanked wheels for {name}=={version}')
    return hashes


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--service',choices=SERVICES,action='append')
    args=parser.parse_args()
    for service in args.service or SERVICES:
        result=subprocess.run(['docker','compose','exec','-T',service,'python','-c',
            'import importlib.metadata,json; print(json.dumps({d.metadata["Name"]:d.version for d in importlib.metadata.distributions()}))'],
            cwd=ROOT,check=True,capture_output=True,text=True)
        graph=json.loads(result.stdout)
        graph={name:version for name,version in graph.items() if not name.lower().startswith('porygon-') and name.lower()!='pip'}
        graph['setuptools']='80.9.0';graph['wheel']='0.45.1'
        lines=['# Python 3.13 Linux service runtime, test and build dependency graph.',
            '# Regenerate intentionally with scripts/lock_service_dependencies.py; hashes include compatible wheels.']
        for name,version in sorted(graph.items(),key=lambda pair:pair[0].lower()):
            lines.append(f'{name}=={version} '+' '.join('--hash=sha256:'+digest for digest in wheel_hashes(name,version)))
        (ROOT/service/'requirements.lock').write_text('\n'.join(lines)+'\n')
        print(f'{service}: wrote {len(graph)} pinned dependency entries')


if __name__=='__main__':main()
