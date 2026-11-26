"""Hash the complete nonignored source inventory, including untracked source."""
import hashlib
import json
from pathlib import Path
import subprocess
ROOT=Path(__file__).resolve().parents[1]


def source_identity(root=ROOT):
    raw=subprocess.run(['git','ls-files','-z','--cached','--others','--exclude-standard'],cwd=root,capture_output=True,check=True).stdout
    names=sorted(set(name for name in raw.decode().split('\0') if name and not name.startswith('plans/')))
    files={}
    for name in names:
        path=root/name
        if path.is_symlink():raise ValueError('Release source cannot include symlinks')
        if path.is_file():files[name]=hashlib.sha256(path.read_bytes()).hexdigest()
    digest=hashlib.sha256(json.dumps(files,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    commit=subprocess.run(['git','rev-parse','HEAD'],cwd=root,capture_output=True,check=True,text=True).stdout.strip()
    return {'commit':commit,'files':files,'tree_sha256':digest,'inventory':'all nonignored files except advisor plans'}


if __name__=='__main__':print(json.dumps(source_identity(),sort_keys=True))
