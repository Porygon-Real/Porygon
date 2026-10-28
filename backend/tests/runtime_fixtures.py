from datetime import datetime,timedelta,timezone
from porygon_api.assessment_service import AssessmentScope
from porygon_api.runtime_evidence import epoch_ns
START=datetime(2026,10,27,tzinfo=timezone.utc)
END=START+timedelta(seconds=10)
SCOPE=AssessmentScope(docker_host_id='host-a',container_id='a'*64,context_hash='b'*64)


def events():
    base=epoch_ns(START)
    shared={'docker_host_id':'host-a','container_id':'a'*64,'sensor_instance_id':'sensor','sensor_epoch':'adapter-a',
        'pid_namespace_start_ns':base-10000000000,'exe_from_memfd':False,'exe_writable':False}
    parent=dict(shared,event_id='1'*64,channel='process',process_pid=100,process_ppid=1,process_start_ns=base-5000000000,
        parent_start_ns=base-9000000000,time_nano=base+500000000,executable='/usr/bin/python',exec_return_value=0,event_direction='<')
    child=dict(shared,event_id='2'*64,channel='process',process_pid=101,process_ppid=100,process_start_ns=base+1000000000,
        parent_start_ns=base-5000000000,time_nano=base+2000000000,executable='/tmp/helper',exec_return_value=0,event_direction='<')
    child['exe_writable']=True
    network=dict(shared,event_id='3'*64,channel='kernel',process_pid=101,process_ppid=100,process_start_ns=base+1000000000,
        parent_start_ns=base-5000000000,time_nano=base+3000000000,runtime_action='net_outbound',return_value=0,
        remote_address='192.0.2.1',remote_port=443)
    return [parent,child,network]
