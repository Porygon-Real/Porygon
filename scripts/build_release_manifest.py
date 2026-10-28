"""Generate local image SBOMs and a source-bound release manifest; never publish."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
try:
    from scripts.check_release_manifest import ROOT,SERVICES,validate
    from scripts.source_identity import source_identity
except ModuleNotFoundError:
    from check_release_manifest import ROOT,SERVICES,validate
    from source_identity import source_identity


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--image',action='append',required=True,help='service=local immutable image ID');args=parser.parse_args()
    images=dict(item.split('=',1) for item in args.image)
    if set(images)!=set(SERVICES):parser.error('Exactly five service=image entries required')
    if args.output.exists():parser.error('Use a new output directory')
    args.output.mkdir(mode=0o700,parents=True)
    source=source_identity();entries={}
    for service,image in images.items():
        sbom=args.output/(service+'.spdx.json')
        subprocess.run(['syft',image,'-o','spdx-json='+str(sbom)],check=True,capture_output=True)
        sbom_hash=hashlib.sha256(sbom.read_bytes()).hexdigest()
        binding={'tool':'syft','image_id':image,'source_tree_sha256':source['tree_sha256'],'sbom_sha256':sbom_hash}
        binding_path=args.output/(service+'.sbom-binding.json');binding_path.write_text(json.dumps(binding,sort_keys=True))
        entries[service]={'image_id':image,'lock_sha256':hashlib.sha256((ROOT/service/'requirements.lock').read_bytes()).hexdigest(),
            'sbom_path':sbom.name,'sbom_sha256':sbom_hash,'sbom_binding_path':binding_path.name,
            'sbom_binding_sha256':hashlib.sha256(binding_path.read_bytes()).hexdigest()}
    manifest=args.output/'release-manifest.json'
    manifest.write_text(json.dumps({'contract':'porygon.release-manifest','source':source,'services':entries,'acceptance':'not-recorded'},sort_keys=True,indent=2))
    print(json.dumps(validate(manifest)))


if __name__=='__main__':main()
