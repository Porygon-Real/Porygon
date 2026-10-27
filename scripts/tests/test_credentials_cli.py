"""Provisioning files are private, exclusive, and never leak generated material."""
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
from unittest.mock import patch

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('credential_cli', ROOT/'scripts/porygon_credentials.py')
cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cli)


def test_private_file_exclusive_and_mode(tmp_path):
    target = tmp_path/'token'
    cli.private_write(target, 'private-material\n')
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    with pytest.raises(FileExistsError):
        cli.private_write(target, 'replacement')
    link = tmp_path/'symlink'
    link.symlink_to(target)
    with pytest.raises(FileExistsError):
        cli.private_write(link,'replacement')
    assert target.read_text() == 'private-material\n'


def test_cli_does_not_print_secret(tmp_path, capsys):
    admin = tmp_path/'admin'
    admin.write_text('admin-private')
    target = tmp_path/'token'
    env = tmp_path/'worker.env'
    generated = 'generated-secret-' + 'x'*43
    with patch.object(cli.secrets,'token_urlsafe',return_value=generated), patch.object(
            cli,'secure_open',return_value=io.BytesIO(json.dumps({'credential_id':'id'}).encode())):
        assert cli.main(['--admin-token-file',str(admin),'enroll','--subject','service:collector',
            '--service','collector','--instance','collector-a','--host','host-a',
            '--output',str(target),'--worker-env',str(env)]) == 0
    output = capsys.readouterr()
    assert generated not in output.out + output.err
    assert 'admin-private' not in output.out + output.err
    assert env.read_text() == 'COLLECTOR_API_TOKEN='+generated+'\n'
    assert stat.S_IMODE(env.stat().st_mode) == 0o600


def test_authenticated_overlay_requires_distinct_inputs_and_no_shared_fallback():
    services = yaml.safe_load((ROOT/'compose.authenticated.yaml').read_text())['services']
    assert services['backend']['environment']['PORYGON_ACCESS_MODE'] == 'authenticated'
    assert services['responder']['environment']['PORYGON_ACCESS_MODE'] == 'authenticated'
    for name in ('collector','telemetry','scanner','responder'):
        environment = services[name]['environment']
        token = environment['PORYGON_INTERNAL_API_TOKEN']
        assert token.startswith('${'+name.upper()+'_API_TOKEN:?')
        assert 'PORYGON_INTERNAL_API_TOKEN' not in token
        assert not any(key in environment for key in ('PORYGON_OPERATOR_API_TOKEN','PORYGON_AI_API_KEY','PORYGON_DATABASE_URL'))


def test_plaintext_remote_origin_rejected_before_reading_credentials(tmp_path):
    with pytest.raises(SystemExit) as failure:
        cli.main(['--url','http://remote.example','--admin-token-file',str(tmp_path/'missing'),'list'])
    assert failure.value.code==2


def test_overlay_missing_worker_inputs_fails_configuration(tmp_path):
    import subprocess
    env = {key:value for key,value in os.environ.items() if key in {'PATH','HOME','DOCKER_CONFIG'}}
    result=subprocess.run(['docker','compose','--env-file','/dev/null','-f',
                           str(ROOT/'compose.authenticated.yaml'),'config','--quiet'],
                           env=env,capture_output=True,text=True)
    assert result.returncode!=0
    assert 'API_TOKEN' in result.stderr


def test_redirect_transport_never_forwards_credentials():
    import urllib.request
    import urllib.error
    request=urllib.request.Request('https://trusted.example/operator/v1/credentials',
        data=b'private-body',headers={'Authorization':'Bearer private','X-Porygon-Operator-Token':'private'})
    handler=cli.NoCredentialRedirects()
    for target in ['http://remote.example/collect','https://other.example/collect','https://trusted.example/other']:
        with pytest.raises(urllib.error.HTTPError) as denied:
            handler.redirect_request(request,None,302,'redirect',{},target)
        assert denied.value.code==302
