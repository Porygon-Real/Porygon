from unittest.mock import Mock

import pytest
from docker.errors import NotFound

from porygon_collector.normalizer import normalize_event
from porygon_collector.spool import OutboxStore
from test_normalizer import FakeDockerAPI


def event(action='exec_start', kind='container'):
    return {'Type': kind, 'Action': action, 'Actor': {
        'ID': 'a' * 64, 'Attributes': {'container': 'a' * 64}},
        'timeNano': 1784628000000000000}


def test_exec_burst_uses_one_inspection_and_preserves_events(tmp_path):
    store = OutboxStore(str(tmp_path / 'queue.db'), max_events=1000)
    api = Mock(wraps=FakeDockerAPI())
    identities = set()
    for i in range(1000):
        raw = event()
        raw['timeNano'] += i
        identities.add(normalize_event(api, store, 'host-a', raw)['event_id'])
    assert len(identities) == 1000
    assert api.inspect_container.call_count == 1
    assert api.inspect_image.call_count == 1


@pytest.mark.parametrize('action,kind', [
    ('start','container'), ('die','container'), ('stop','container'),
    ('pause','container'), ('unpause','container'), ('rename','container'),
    ('update','container'), ('connect','network'), ('disconnect','network'),
])
def test_mutations_refresh_even_when_cache_is_fresh(tmp_path, action, kind):
    store = OutboxStore(str(tmp_path / 'queue.db'), max_events=100)
    api = Mock(wraps=FakeDockerAPI())
    normalize_event(api, store, 'host-a', event())
    normalize_event(api, store, 'host-a', event(action, kind))
    assert api.inspect_container.call_count == 2


@pytest.mark.parametrize('elapsed', [30, 31, -1])
def test_expired_or_future_cache_refreshes(tmp_path, monkeypatch, elapsed):
    monkeypatch.setattr('porygon_collector.spool.time.time', lambda: 100)
    store = OutboxStore(str(tmp_path / 'queue.db'), max_events=100)
    api = Mock(wraps=FakeDockerAPI())
    normalize_event(api, store, 'host-a', event())
    monkeypatch.setattr('porygon_collector.spool.time.time', lambda: 100 + elapsed)
    normalize_event(api, store, 'host-a', event())
    assert api.inspect_container.call_count == 2


def test_cache_survives_restart_but_never_crosses_hosts(tmp_path):
    path = str(tmp_path / 'queue.db')
    api = Mock(wraps=FakeDockerAPI())
    normalize_event(api, OutboxStore(path, max_events=100), 'host-a', event())
    store = OutboxStore(path, max_events=100)
    normalize_event(api, store, 'host-a', event())
    assert api.inspect_container.call_count == 1
    api.inspect_container.side_effect = NotFound('removed')
    foreign = normalize_event(api, store, 'host-b', event())
    assert foreign['container_snapshot'] == {}
    assert foreign['image_id'] is None
    assert api.inspect_container.call_count == 2


def test_destroy_replay_preserves_last_identity(tmp_path):
    store = OutboxStore(str(tmp_path / 'queue.db'), max_events=100)
    api = Mock(wraps=FakeDockerAPI())
    original = normalize_event(api, store, 'host-a', event())
    api.inspect_container.side_effect = NotFound('removed')
    destroyed = normalize_event(api, store, 'host-a', event('destroy'))
    assert destroyed['image_id'] == original['image_id']
    replay = normalize_event(api, store, 'host-a', event('destroy'))
    assert replay['image_id'] == original['image_id']
    assert replay['event_id'] == destroyed['event_id']


def test_failed_refresh_does_not_extend_freshness(tmp_path, monkeypatch):
    monkeypatch.setattr('porygon_collector.spool.time.time', lambda: 100)
    store = OutboxStore(str(tmp_path / 'queue.db'), max_events=100)
    api = Mock(wraps=FakeDockerAPI())
    normalize_event(api, store, 'host-a', event())
    monkeypatch.setattr('porygon_collector.spool.time.time', lambda: 131)
    api.inspect_container.side_effect = NotFound('temporarily missing')
    assert normalize_event(api, store, 'host-a', event())['image_id']
    assert store.get_cached_container('a' * 64, docker_host_id='host-a', max_age_seconds=30) is None
