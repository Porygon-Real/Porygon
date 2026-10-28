"""Failed exec, pending connect and non-sensitive writes cannot train positive features."""
from porygon_api.evidence_features import extract_features


def event(identifier,**fields):
    return dict(event_id=identifier,channel='process',exec_return_value=0,event_direction='<',exe_from_memfd=False,exe_writable=False,**fields)


def test_failed_exec_does_not_become_observed_memfd_execution():
    row=event('exec');row.update(exec_return_value=-2,exe_from_memfd=True,exe_writable=True)
    result=extract_features({'events':[row],'edges':[],'coverage':{'unavailable_identity_events':0}})
    assert result['values']['memfd_executions']==0
    assert result['values']['writable_executions']==0
    assert result['observations']['memfd_execution']=='unavailable'


def test_pending_connection_and_zero_byte_write_are_not_completed_features():
    process=event('exec')
    network={'event_id':'net','channel':'kernel','runtime_action':'net_outbound','return_value':-115,'remote_address':'192.0.2.1','remote_port':443}
    write={'event_id':'write','channel':'kernel','runtime_action':'file_write','return_value':0,'file_path':'/etc/example'}
    edges=[{'source':'exec','target':row['event_id'],'certainty':'observed','relation':'same_observed_process_lifetime'} for row in (network,write)]
    result=extract_features({'events':[process,network,write],'edges':edges,'coverage':{'unavailable_identity_events':0}})
    assert result['values']['attributed_connections']==0
    assert result['values']['attributed_sensitive_writes']==0
    write.update(return_value=1,file_path='/tmp/example')
    assert extract_features({'events':[process,write],'edges':[edges[1]],'coverage':{'unavailable_identity_events':0}})['values']['attributed_sensitive_writes']==0
