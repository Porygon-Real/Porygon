from porygon_api.runtime_evidence import build_bundle
from runtime_fixtures import events,SCOPE,START,END


def test_completed_observed_child_network_matches_once():
    result=build_bundle(events(),SCOPE,START,END,{'/usr/bin/python'})
    assert sum(row['rule_id']=='POR-EVD-CHILD-NET' for row in result['findings'])==1


def test_approved_executable_and_in_progress_connection_are_negative_controls():
    source=events()
    assert not build_bundle(source,SCOPE,START,END,{'/usr/bin/python','/tmp/helper'})['findings']
    source[-1]['return_value']=-115
    assert not build_bundle(source,SCOPE,START,END,{'/usr/bin/python'})['findings']


def test_memfd_creation_is_not_memfd_execution():
    source=events();source[-1].update(runtime_action='memfd_create',return_value=4)
    assert not build_bundle(source,SCOPE,START,END,{'/usr/bin/python'})['findings']
    source[1]['exe_from_memfd']=True
    assert any(row['rule_id']=='POR-EVD-MEMFD-EXEC' for row in build_bundle(source,SCOPE,START,END,{'/usr/bin/python'})['findings'])


def test_positive_sensitive_write_requires_observed_parent_and_written_bytes():
    source=events();source[-1].update(runtime_action='file_write',return_value=1,file_path='/etc/fixture')
    assert any(row['rule_id']=='POR-EVD-SENSITIVE-WRITE' for row in build_bundle(source,SCOPE,START,END,{'/usr/bin/python'})['findings'])
    source[-1]['return_value']=0
    assert not build_bundle(source,SCOPE,START,END,{'/usr/bin/python'})['findings']
