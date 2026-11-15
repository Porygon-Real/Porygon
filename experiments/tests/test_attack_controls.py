"""Cross-service contracts use the real collector normalizer, not a hand-built snapshot."""
from pathlib import Path
import sys
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[2]
for service in ('backend', 'collector'):
    sys.path.insert(0, str(ROOT / service / 'src'))

from experiments.attacks.catalog import catalog, digest  # noqa: E402
from experiments.attacks.replay import replay  # noqa: E402


def test_catalog_has_stable_hashes_and_two_way_pairs():
    document = catalog()
    assert digest(document) == digest(catalog())
    pairs = {}
    for case in document['cases']:
        assert case['content_sha256'] == digest({k: v for k, v in case.items() if k != 'content_sha256'})
        pairs.setdefault(case['pair_id'], set()).add(case['label'])
    assert all('positive' in labels and labels & {'control', 'unknown'} for labels in pairs.values())
    assert all(case['software_assertion_passed'] for case in replay()['cases'])


def test_real_collector_snapshot_drives_exposure_without_configured_port_confusion():
    from porygon_collector.normalizer import build_container_snapshot
    from porygon_api.vulnerability import assess_exposure

    class DockerFixture:
        def inspect_container(self, container_id):
            return {'Id': container_id, 'Image': 'sha256:'+'b'*64,
                    'State': {'Running': True, 'StartedAt': '2026-01-01T00:00:00Z'},
                    'Config': {'Image': 'owned-fixture', 'ExposedPorts': {'8080/tcp': {}}},
                    'HostConfig': {'PortBindings': {'8080/tcp': [{'HostIp': '', 'HostPort': ''}]}},
                    'NetworkSettings': {'Ports': {'8080/tcp': [{'HostIp': '::1', 'HostPort': '12345'}]}}}
        def inspect_image(self, image_id):
            return {'Id': image_id, 'RepoDigests': []}

    snapshot = build_container_snapshot(DockerFixture(), 'a'*64)
    # Host binding belongs to the authenticated ingest/route, inspector time to
    # the collector. Both are required; identity.last_seen is not inspector time.
    snapshot['docker_host_id'] = 'fixture-host'
    event = dict(container_id='a'*64, docker_host_id='fixture-host', executable='/usr/bin/curl',
                 occurred_at=snapshot['observed_at'], exec_return_value=0, event_direction='<')
    def evaluate():
        return assess_exposure(finding={'package_name': 'curl'}, container_snapshots=[snapshot],
                               process_events=[event], as_of=datetime.now(timezone.utc))
    assert evaluate()['evidence_stage'] == 'runtime_observed_and_port_published'
    snapshot['network_settings']['ports'] = {}
    assert evaluate()['evidence_stage'] == 'runtime_observed'
    snapshot['state']['running'] = False
    assert evaluate()['evidence_stage'] == 'package_present'
    snapshot['state']['running'] = True
    snapshot.pop('observed_at')
    assert evaluate()['evidence_stage'] == 'package_present'


def test_real_destroy_event_does_not_promote_cached_running_state(tmp_path):
    from docker.errors import NotFound
    from porygon_collector.normalizer import normalize_event
    from porygon_collector.spool import OutboxStore
    from porygon_api.vulnerability import assess_exposure
    class RemovedDocker:
        def inspect_container(self, cid):
            raise NotFound('owned test container removed')
    store=OutboxStore(str(tmp_path/'outbox.db'),max_events=10)
    cid='a'*64
    inspected='2026-01-01T00:00:00Z'
    store.cache_container(cid,{'container':{'id':cid},'state':{'running':True,'started_at':inspected},
                              'observed_at':inspected},docker_host_id='host')
    event=normalize_event(RemovedDocker(),store,'host',{'Type':'container','Action':'destroy',
        'Actor':{'ID':cid,'Attributes':{}},'timeNano':1767312000000000000})
    snapshot=event['container_snapshot']
    assert snapshot['observed_at']==inspected and snapshot['state']['running'] is True
    assert snapshot['lifecycle_observation']['action']=='destroy'
    snapshot['docker_host_id']='host'
    result=assess_exposure(finding={'package_name':'curl'},container_snapshots=[snapshot],process_events=[],
                           as_of=datetime(2026,1,3,tzinfo=timezone.utc))
    assert result['evidence_stage']=='package_present'
    assert not result['evidence']['container_running']
    assert result['evidence']['container_contexts'][0]['state_basis']=='terminal_lifecycle'
