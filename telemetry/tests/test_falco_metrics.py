from porygon_telemetry.falco_metrics import parse_metrics


def test_exact_pinned_epoch_names_and_scientific_counters():
    result=parse_metrics('''falcosecurity_falco_start_timestamp_nanoseconds 1720000000000000001
falcosecurity_falco_reload_timestamp_nanoseconds 1720000000000000002
falcosecurity_scap_n_evts_total 1e3
falcosecurity_scap_n_drops_total 0
falcosecurity_scap_n_drops_cpu_total{cpu="0"} 999
''')
    assert result['metrics']['falco_start_ns']==1720000000000000001
    assert result['metrics']['falco_events']==1000
    assert result['metrics']['falco_drops']==0
    assert '1720000000000000001' in result['source_epoch']


def test_missing_epoch_does_not_imply_complete_capture():
    result=parse_metrics('falcosecurity_scap_n_drops_total 0')
    assert result['source_epoch'] is None and result['source_loss']=='unknown'
