import pytest
from porygon_api.runtime_evidence import build_bundle
from runtime_fixtures import events,SCOPE,START,END


def test_replay_is_deterministic_and_every_support_is_in_scope():
    source=events();left=build_bundle(source,SCOPE,START,END,{'/usr/bin/python'});right=build_bundle(list(reversed(source)),SCOPE,START,END,{'/usr/bin/python'})
    assert left==right
    assert left['findings']
    assert all(set(row['supporting_ids'])<={event['event_id'] for event in source} for row in left['findings'])


@pytest.mark.parametrize('field,value',[('sensor_epoch','other'),('process_start_ns',1),('pid_namespace_start_ns',2)])
def test_pid_match_cannot_cross_source_epoch_or_lifetime(field,value):
    source=events();source[-1][field]=value
    result=build_bundle(source,SCOPE,START,END,{'/usr/bin/python'})
    assert not result['findings']
    assert not any(edge['relation']=='same_observed_process_lifetime' and edge['certainty']=='observed' for edge in result['edges'])


def test_other_host_is_rejected_instead_of_joined():
    source=events();source[-1]['docker_host_id']='other-host'
    with pytest.raises(ValueError):build_bundle(source,SCOPE,START,END,set())


def test_missing_metadata_abstains():
    source=events()
    for row in source:row['process_start_ns']=None
    result=build_bundle(source,SCOPE,START,END,set())
    assert not result['findings'] and result['coverage']['unavailable_identity_events']==3
