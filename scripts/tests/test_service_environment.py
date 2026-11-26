"""Compose settings are explicit and service credentials stay least-privileged."""
import ast
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
APPLICATIONS = ('backend', 'collector', 'telemetry', 'responder', 'scanner')
PACKAGES = {'backend': 'porygon_api', **{
    name: 'porygon_' + name for name in APPLICATIONS if name != 'backend'}}


def services():
    return yaml.safe_load((ROOT / 'compose.yaml').read_text())['services']


def test_every_service_has_an_explicit_environment_allowlist():
    for name, service in services().items():
        assert 'env_file' not in service, f'{name} imports a wholesale secret file'


def test_only_backend_and_database_receive_database_credentials():
    for name, service in services().items():
        keys = set(service.get('environment', {}))
        if name != 'backend':
            assert 'PORYGON_OPERATOR_API_TOKEN' not in keys, name
            assert 'PORYGON_AI_API_KEY' not in keys, name
            assert not any(key.startswith('PORYGON_DB_') for key in keys), name
        if name != 'postgres':
            assert not any(key.startswith('POSTGRES_') for key in keys), name
    assert set(services()['postgres']['environment']) == {
        'POSTGRES_DB', 'POSTGRES_USER', 'POSTGRES_PASSWORD'}


def test_every_application_setting_has_an_explicit_mapping():
    configured = services()
    for name in APPLICATIONS:
        tree = ast.parse((ROOT / name / 'src' / PACKAGES[name] / 'config.py').read_text())
        settings = next(node for node in tree.body if isinstance(node, ast.ClassDef)
                        and node.name == 'Settings')
        fields = {node.target.id for node in settings.body if isinstance(node, ast.AnnAssign)}
        missing = {'PORYGON_' + field.upper() for field in fields} - set(
            configured[name]['environment'])
        assert not missing, f'{name} has unmapped Settings keys: {sorted(missing)}'


def test_collector_scanner_responder_and_telemetry_have_only_the_service_token():
    for name in APPLICATIONS[1:]:
        environment = services()[name]['environment']
        credentials = {key for key in environment if any(
            marker in key for marker in ('TOKEN', 'PASSWORD', 'API_KEY'))}
        assert credentials == {'PORYGON_INTERNAL_API_TOKEN'}, name
