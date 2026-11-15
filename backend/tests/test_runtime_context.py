import pytest
from porygon_api.evidence_features import extract_features
from porygon_api.runtime_evidence import build_bundle, epoch_ns, PROCESS_CONTEXT_CONTRACT
from runtime_fixtures import events, SCOPE, START, END


def old_context():
    source = events()
    shift = 3600 * 10**9
    for event in source:
        event['process_start_ns'] -= shift
        event['parent_start_ns'] -= shift
        event['pid_namespace_start_ns'] -= shift
    for event in source[:2]:
        event['time_nano'] -= shift
    return source


def test_long_lived_exact_identity_attributes_without_creating_old_findings():
    source = old_context()
    source[1]['exe_from_memfd'] = True
    bundle = build_bundle(source[2:], SCOPE, START, END, {'/usr/bin/python'},
                          context={'events': source[:2], 'status': 'complete'})
    assert bundle['contract'] == PROCESS_CONTEXT_CONTRACT
    assert {x['rule_id'] for x in bundle['findings']} == {'POR-EVD-CHILD-NET', 'POR-EVD-WRITABLE-NET'}
    assert extract_features(bundle)['values']['memfd_executions'] == 0
    assert extract_features(bundle)['values']['observed_parent_edges'] == 0
    assert bundle['coverage']['async_connection_completion'] == 'unsupported'


@pytest.mark.parametrize('field,value', [('process_start_ns', 1), ('sensor_epoch', 'new'),
                                        ('pid_namespace_start_ns', 1), ('process_start_ns', None)])
def test_old_context_cannot_cross_reused_identity(field, value):
    source = old_context()
    source[2][field] = value
    bundle = build_bundle(source[2:], SCOPE, START, END, set(),
                          context={'events': source[:2], 'status': 'complete'})
    assert not bundle['findings']
    assert bundle['coverage']['unattributed_kernel_events'] == 1


def test_latest_successful_exec_image_wins_with_same_process_lifetime():
    source = old_context()
    replacement = dict(source[1], event_id='4'*64, time_nano=epoch_ns(START)-1,
                       executable='/usr/bin/approved', exe_writable=False)
    bundle = build_bundle(source[2:], SCOPE, START, END, {'/usr/bin/approved'},
                          context={'events': source[:2]+[replacement], 'status': 'complete'})
    assert not bundle['findings']
    attribution = next(edge for edge in bundle['edges'] if edge['relation']=='same_observed_process_lifetime')
    assert attribution['source'] == replacement['event_id']


@pytest.mark.parametrize('path', ['/sbin/fixture', '/usr/sbin/fixture'])
def test_sensitive_path_parity_is_new_contract_only(path):
    source = events()
    source[-1].update(runtime_action='file_write', return_value=1, file_path=path)
    assert not build_bundle(source, SCOPE, START, END, set())['findings']
    bundle = build_bundle(source, SCOPE, START, END, set(), context={'events': [], 'status': 'complete'})
    assert {x['rule_id'] for x in bundle['findings']} == {'POR-EVD-SENSITIVE-WRITE'}


def test_future_context_wrong_scope_and_failed_exec_are_rejected():
    for mutation in ({'time_nano': epoch_ns(START)}, {'docker_host_id': 'other'}, {'exec_return_value': -1}):
        source = old_context()
        source[1].update(mutation)
        with pytest.raises(ValueError):
            build_bundle(source[2:], SCOPE, START, END, set(), context={'events': source[:2]})


def test_context_lookup_uses_exact_keys_and_returns_latest_preceding_exec():
    from porygon_api.runtime_evidence import query_context_events
    from types import SimpleNamespace

    source = old_context()
    rows = {row['process_pid']: SimpleNamespace(**row) for row in source[:2]}

    class DB:
        calls = []
        def scalar(self, query):
            compiled = query.compile(compile_kwargs={'literal_binds': True})
            text = str(compiled)
            self.calls.append(text)
            for pid in (100, 101):
                if f'process_exec_events.process_pid = {pid}' in text:
                    return rows[pid]
            return None

    db = DB()
    result = query_context_events(db, SCOPE, START, END, source[2:])
    assert {e['event_id'] for e in result['events']} == {'1'*64, '2'*64}
    assert result['status'] == 'complete'
    assert all('sensor_epoch =' in q and 'process_start_ns =' in q and 'pid_namespace_start_ns =' in q for q in db.calls)
    assert all('time_nano DESC' in q and 'LIMIT 1' in q for q in db.calls)


def test_context_key_limit_reports_truncation_without_unbounded_queries(monkeypatch):
    from porygon_api import runtime_evidence
    monkeypatch.setitem(runtime_evidence.CONTEXT_CONFIG, 'max_context_keys', 1)
    class DB:
        count = 0
        def scalar(self, query):
            self.count += 1
            return None
    db = DB()
    result = runtime_evidence.query_context_events(db, SCOPE, START, END, events())
    assert db.count == 1
    assert result['status'] == 'truncated'
