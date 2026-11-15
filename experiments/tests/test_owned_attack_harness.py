from types import SimpleNamespace
import json
import pytest
from experiments.attacks import live


def test_harness_refuses_primary_before_any_docker_call(monkeypatch):
    def forbidden(*args):
        raise AssertionError('No Docker call permitted')
    monkeypatch.setattr(live, 'resolve_runtime_binding', forbidden)
    with pytest.raises(ValueError, match='isolated'):
        live.run(SimpleNamespace(compose_project='porygon'))


def test_owned_cleanup_rejects_mounts_and_wrong_run_labels(monkeypatch):
    value={'Config': {'Labels': {live.LABEL:'owned'}}, 'Mounts': [],
           'HostConfig': {'CapDrop':['ALL'], 'NetworkMode':'porygon-attack-control-owned'}}
    monkeypatch.setattr(live,'run_docker',lambda *args:json.dumps([value]))
    assert live.inspect_owned(None,'a'*64,'owned') == value
    for change in ({'Mounts':[{'Type':'bind'}]}, {'Config':{'Labels':{live.LABEL:'other'}}}):
        original=dict(value)
        value.update(change)
        with pytest.raises(RuntimeError,match='isolation'):
            live.inspect_owned(None,'a'*64,'owned')
        value.clear()
        value.update(original)


def test_owned_observable_targets_are_not_excluded_by_falco_labels():
    from pathlib import Path
    rule = (Path(__file__).resolve().parents[2]/'falco/porygon_rules.yaml').read_text()
    assert 'not container.label[com.porygon.protected] = "true"' in rule
    target = live.container_create_argv('sha256:'+'a'*64, 'private', 'owned', 'pass', observable=True)
    peer = live.container_create_argv('sha256:'+'a'*64, 'private', 'owned', 'pass', observable=False)
    labels = [target[index+1] for index, value in enumerate(target) if value=='--label']
    assert 'com.porygon.protected=true' not in labels
    assert 'com.porygon.protected=false' in labels
    assert 'io.porygon.owned-disposable=true' in labels
    assert live.LABEL+'=owned' in labels
    assert 'com.porygon.protected=true' in peer
    assert '--cap-drop=ALL' in target and '--security-opt=no-new-privileges:true' in target
    assert not set(target) & {'--volume', '-v', '--mount', '--privileged', '--publish', '-p'}


def test_live_receipt_refuses_existing_output_before_creating_targets(monkeypatch, tmp_path):
    output = tmp_path/'receipt.json'
    output.write_text('preserve previous receipt')
    binding = SimpleNamespace(services={'backend': {'container_id':'b'*64, 'image_id':'sha256:'+'a'*64}},
                              to_dict=lambda: {})
    monkeypatch.setattr(live,'resolve_runtime_binding',lambda *args:binding)
    calls=[]
    def docker(*args, **kwargs):
        calls.append(args)
        return 'disabled'
    monkeypatch.setattr(live,'run_docker',docker)
    with pytest.raises(FileExistsError):
        live.run(SimpleNamespace(compose_project='porygon-service-trust', docker_context='default',
                                 api_origin='http://127.0.0.1:3000', output=output))
    assert output.read_text() == 'preserve previous receipt'
    assert all(call[1]=='exec' for call in calls)


def test_network_probe_keeps_connect_blocking_with_outer_deadlines():
    import ast
    tree = ast.parse(live.WORK)
    assert not any(isinstance(node, ast.Attribute) and node.attr in {'settimeout', 'setblocking'}
                   for node in ast.walk(tree))
    # The nested owned helper command must also retain blocking socket mode.
    assert 'settimeout' not in live.WORK and 'setblocking' not in live.WORK
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Attribute) and node.func.attr=='run']
    assert calls and all(any(k.arg=='timeout' and isinstance(k.value, ast.Constant) and k.value.value==5
                             for k in call.keywords) for call in calls)
