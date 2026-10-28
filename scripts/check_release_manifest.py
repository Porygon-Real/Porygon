"""Verify a local release's source, lock, image and SBOM identities without publishing."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
try:
    from scripts.source_identity import source_identity
except ModuleNotFoundError:
    from source_identity import source_identity

ROOT=Path(__file__).resolve().parents[1]
SERVICES=('backend','collector','telemetry','responder','scanner')


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def confined(root,name):
    if not isinstance(name,str) or not name or Path(name).is_absolute() or '..' in Path(name).parts:
        raise ValueError('Artifact path must be relative and confined')
    candidate=root/name
    if any(part.is_symlink() for part in (candidate,*candidate.parents) if part!=root.parent):
        raise ValueError('Release artifacts cannot traverse symlinks')
    candidate=candidate.resolve()
    if not candidate.is_relative_to(root.resolve()) or not candidate.is_file():raise ValueError('Missing confined artifact')
    return candidate


def validate(manifest_path):
    path=Path(manifest_path).resolve()
    if path.stat().st_size>4*1024*1024:raise ValueError('Release manifest too large')
    value=json.loads(path.read_text())
    if value.get('contract')!='porygon.release-manifest':raise ValueError('Unknown release contract')
    source=value.get('source',{})
    if not re.fullmatch(r'[a-f0-9]{40}',source.get('commit','')):raise ValueError('Full source commit required')
    subprocess.run(['git','cat-file','-e',source['commit']+'^{commit}'],cwd=ROOT,check=True,capture_output=True)
    files=source.get('files')
    if not isinstance(files,dict) or not files:raise ValueError('Source file hashes required')
    for name,digest in files.items():
        if not re.fullmatch(r'[a-f0-9]{64}',digest) or sha(confined(ROOT,name))!=digest:raise ValueError('Source hash mismatch')
    actual_source=source_identity()
    if files!=actual_source['files'] or source.get('tree_sha256')!=actual_source['tree_sha256'] or source['commit']!=actual_source['commit']:
        raise ValueError('Release source identity differs from the complete current source inventory')
    services=value.get('services',{})
    if set(services)!=set(SERVICES):raise ValueError('All five service images are required')
    for service,entry in services.items():
        if entry.get('lock_sha256')!=sha(ROOT/service/'requirements.lock'):raise ValueError('Dependency lock mismatch')
        image=entry.get('image_id','')
        if not re.fullmatch(r'sha256:[a-f0-9]{64}',image):raise ValueError('Immutable image ID required')
        info=json.loads(subprocess.run(['docker','image','inspect',image],capture_output=True,check=True).stdout)[0]
        if info['Id']!=image:raise ValueError('Image identity mismatch')
        labels=info.get('Config',{}).get('Labels',{}) or {}
        if (labels.get('org.opencontainers.image.revision')!=source['commit'] or
            labels.get('com.porygon.source-tree-sha256')!=source['tree_sha256'] or
            labels.get('com.porygon.dependency-lock-sha256')!=entry['lock_sha256']):
            raise ValueError('Image provenance labels differ from source and dependency graph')
        sbom=confined(path.parent,entry['sbom_path'])
        if sha(sbom)!=entry['sbom_sha256']:raise ValueError('SBOM hash mismatch')
        document=json.loads(sbom.read_text())
        binding=confined(path.parent,entry['sbom_binding_path'])
        receipt=json.loads(binding.read_text())
        if (sha(binding)!=entry['sbom_binding_sha256'] or receipt.get('image_id')!=image or
            receipt.get('source_tree_sha256')!=source['tree_sha256'] or receipt.get('sbom_sha256')!=entry['sbom_sha256'] or
            receipt.get('tool')!='syft'):
            raise ValueError('SBOM generation receipt does not bind this exact source/image')
        if not (document.get('spdxVersion') and document.get('packages')) and not (document.get('bomFormat')=='CycloneDX' and document.get('components')):
            raise ValueError('Nonempty SPDX/CycloneDX SBOM required')
    return {'valid':True,'contract':value['contract'],'services':list(SERVICES),'empirical_acceptance':value.get('acceptance','not-recorded')}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--manifest',type=Path,required=True);args=parser.parse_args()
    try:result=validate(args.manifest)
    except (ValueError,OSError,KeyError,subprocess.SubprocessError,json.JSONDecodeError) as exc:
        print(json.dumps({'valid':False,'error_category':type(exc).__name__}));return 1
    print(json.dumps(result));return 0


if __name__=='__main__':raise SystemExit(main())
