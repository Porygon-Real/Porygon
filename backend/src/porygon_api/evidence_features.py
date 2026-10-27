"""Distinct structural contract; absent sensor fields are not benign zeroes."""
CONTRACT='porygon.evidence-features'
FEATURE_NAMES=('observed_parent_edges','attributed_connections','attributed_sensitive_writes','memfd_executions','writable_executions')


def extract_features(bundle):
    events=bundle['events']
    def observed_flag(name):
        flags=[event.get(name) for event in events if event['channel']=='process']
        return 'observed' if True in flags else 'not_observed' if flags and all(flag is False for flag in flags) else 'unavailable'
    known={event['event_id']:event for event in events}
    attributions=[edge for edge in bundle['edges'] if edge['certainty']=='observed' and edge['relation']=='same_observed_process_lifetime']
    values={
        'observed_parent_edges':sum(edge['certainty']=='observed' and edge['relation']=='parent_process' for edge in bundle['edges']),
        'attributed_connections':sum(known[edge['target']]['runtime_action']=='net_outbound' for edge in attributions),
        'attributed_sensitive_writes':sum(known[edge['target']]['runtime_action']=='file_write' for edge in attributions),
        'memfd_executions':sum(event.get('exe_from_memfd') is True for event in events if event['channel']=='process'),
        'writable_executions':sum(event.get('exe_writable') is True for event in events if event['channel']=='process'),
    }
    return {'contract':CONTRACT,'values':values,'observations':{'memfd_execution':observed_flag('exe_from_memfd'),
        'writable_execution':observed_flag('exe_writable')},'identity_coverage':bundle['coverage']}


from typing import Annotated,Literal
from pydantic import BaseModel,ConfigDict,Field,model_validator


class EvidenceFeatureDocument(BaseModel):
    model_config=ConfigDict(extra='forbid',strict=True,allow_inf_nan=False)
    contract: Literal['porygon.evidence-features']
    values: dict[str,Annotated[float,Field(ge=0,le=1000000)]]
    observations: dict[str,Literal['observed','not_observed','unavailable']]
    identity_coverage: dict

    @model_validator(mode='after')
    def known_contract(self):
        if set(self.values)!=set(FEATURE_NAMES) or set(self.observations)!={'memfd_execution','writable_execution'}:
            raise ValueError('Exact feature and observation schemas are required')
        unavailable=self.identity_coverage.get('unavailable_identity_events')
        if not isinstance(unavailable,int) or isinstance(unavailable,bool) or not 0<=unavailable<=10000:
            raise ValueError('Identity coverage must declare a bounded unavailable count')
        return self
