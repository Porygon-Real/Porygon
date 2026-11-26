"""Bounded pinned-Falco aggregate counter parser; never sum per-CPU duplicates."""
import re
from decimal import Decimal,InvalidOperation

ALIASES={
    'falco_events':('falcosecurity_scap_n_evts','falcosecurity_scap_n_evts_total'),
    'falco_drops':('falcosecurity_scap_n_drops','falcosecurity_scap_n_drops_total'),
    'falco_output_drops':('falcosecurity_falco_outputs_queue_num_drops','falcosecurity_falco_outputs_queue_num_drops_total'),
    'falco_start_ns':('falcosecurity_falco_start_ts','falcosecurity_falco_start_timestamp','falcosecurity_falco_start_timestamp_nanoseconds'),
    'falco_reload_ns':('falcosecurity_falco_ruleset_reload_timestamp','falcosecurity_falco_reload_ts','falcosecurity_falco_reload_timestamp_nanoseconds'),
    'host_boot_ns':('falcosecurity_falco_host_boot_ts','falcosecurity_falco_host_boot_timestamp','falcosecurity_falco_host_boot_timestamp_nanoseconds'),
}


def parse_metrics(text):
    if len(text.encode())>1048576:raise ValueError('Falco metrics exceed bounded scrape size')
    values={}
    for line in text.splitlines():
        if not line or line.startswith('#'):continue
        match=re.fullmatch(r'([A-Za-z_:][A-Za-z0-9_:]*)(?:\{([^}]*)\})?\s+([0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)',line.strip())
        if not match:continue
        name,labels,value=match.groups()
        # Aggregate counters only; PID/container/command labels never propagate.
        if labels:continue
        for key,names in ALIASES.items():
            if name in names and key not in values:
                try:number=Decimal(value)
                except InvalidOperation:continue
                if number.is_finite() and 0<=number<=Decimal('1e19') and number==number.to_integral_value():values[key]=int(number)
    epoch_parts=[str(values.get(key,'')) for key in ('falco_start_ns','falco_reload_ns','host_boot_ns')]
    epoch='falco:'+':'.join(epoch_parts) if values.get('falco_start_ns') is not None else None
    drops=values.get('falco_drops')
    return {'metrics':values,'source_epoch':epoch,
        'source_loss':'known-loss' if epoch and drops and drops>0 else 'no-observed-drops' if epoch and drops==0 else 'unknown'}
