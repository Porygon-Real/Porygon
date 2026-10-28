"""Offline full-field profile comparison under an explicitly reviewed analysis policy.

The frozen protocol names comparators but leaves some extractor aggregation and
quality choices open. Their exact implementation is bound in the pre-collection
policy; missing policy/support yields abstention, never inferred benign labels.
"""
from collections import Counter,defaultdict
from copy import deepcopy
from datetime import datetime,timedelta,timezone
import math
from pathlib import Path
import statistics
import sys
from types import SimpleNamespace
ROOT=Path(__file__).resolve().parents[1]
if str(ROOT/'backend/src') not in sys.path:sys.path.insert(0,str(ROOT/'backend/src'))
from porygon_api.baseline import build_profile_document,_summary
from porygon_api.calibrated_rarity import hellinger_distance,novelty_mass,markov_surprisal,empirical_upper_tail_pvalue
from porygon_api.detection import evaluate_detection
from porygon_api.vulnerability import sha256_document
from porygon_api.runtime_evidence import epoch_ns

SCOPES=('ARM-GLOBAL','ARM-TAG','ARM-DIGEST','ARM-CONTEXT')
DETECTORS=('DET-RULES','DET-NOVELTY','DET-FREQUENCY','DET-SEQUENCE','DET-CALIBRATED','DET-HYBRID')
ABLATIONS=('ABL-NO-SEQUENCE','ABL-NO-NOVELTY','ABL-NO-DISTRIBUTION','ABL-NO-NUMERIC','ABL-NO-CONTEXT','ABL-FALLBACK')
COMPONENTS=('categorical_shift','sequence_surprisal','novelty_mass','numeric_tail')
POLICY_IMPLEMENTATION='full-frozen-fields-mean-component-ranks-max-run'


def validate_policy(policy):
    required={'contract','implementation','window_seconds','minimum_process_events','minimum_nonempty_windows',
        'minimum_fit_runs','minimum_calibration_runs','minimum_replicas','scenario_horizon_seconds','alpha','missing_component_policy','quality_justification','review_reference'}
    if set(policy)!=required or policy['contract']!='porygon.frozen-analysis-policy' or policy['implementation']!=POLICY_IMPLEMENTATION:
        raise ValueError('Complete supported pre-collection analysis policy required')
    if policy['alpha']!=0.05 or policy['missing_component_policy']!='abstain':raise ValueError('Frozen nominal coverage and explicit abstention required')
    for name,lower,upper in (('scenario_horizon_seconds',1,3600),('window_seconds',5,3600),('minimum_process_events',1,1000000),('minimum_nonempty_windows',1,100000),('minimum_fit_runs',10,10000),('minimum_calibration_runs',10,10000),('minimum_replicas',3,10000)):
        if type(policy[name]) is not int or not lower<=policy[name]<=upper:raise ValueError('Invalid locked quality/count choice')
    if not all(isinstance(policy[key],str) and 1<=len(policy[key])<=2000 for key in ('quality_justification','review_reference')):raise ValueError('Reviewed quality justification required')
    return policy


def scope_key(trial,scope):
    if scope=='ARM-GLOBAL':return ('all',)
    if scope=='ARM-TAG':return (trial['human_tag'],)
    if scope=='ARM-DIGEST':return (trial['image']['reference'],)
    if scope=='ARM-CONTEXT':return (trial['image']['reference'],trial['runtime_context_hash'])
    raise ValueError('Unknown profile scope')


def decoded_snapshot(snapshot,trial):
    raw={key:value for key,value in snapshot.items() if key!='sha256'}
    if snapshot.get('contract')!='porygon.frozen-study-snapshot' or sha256_document(raw)!=snapshot.get('sha256'):
        raise ValueError('Snapshot identity mismatch')
    scope=snapshot['scope']
    if (scope['docker_host_id']!=trial['docker_host_id'] or scope['container_id']!=trial['container_id'] or
        scope['image_digest']!=trial['image']['reference']):raise ValueError('Snapshot target differs from trial')
    start=datetime.fromisoformat(scope['start']);end=datetime.fromisoformat(scope['end'])
    if start.tzinfo is None or end.tzinfo is None or start>=end:raise ValueError('Invalid snapshot interval')
    if start!=datetime.fromisoformat(trial['timeline']['setup_started_at_utc']) or end!=datetime.fromisoformat(trial['timeline']['cleanup_finished_at_utc']):
        raise ValueError('Snapshot interval differs from the complete trial')
    data={};ids=set()
    for channel in ('process','runtime'):
        rows=[]
        for source in snapshot['events'][channel]:
            row=dict(source);row['occurred_at']=datetime.fromisoformat(row['occurred_at'])
            if (row['event_id'] in ids or row['docker_host_id']!=scope['docker_host_id'] or row['container_id']!=scope['container_id'] or
                row['occurred_at'].tzinfo is None or type(row.get('time_nano')) is not int or not epoch_ns(start)<=row['time_nano']<epoch_ns(end)):raise ValueError('Snapshot row scope mismatch')
            ids.add(row['event_id']);rows.append(SimpleNamespace(**row))
        data[channel]=sorted(rows,key=lambda row:(row.time_nano,row.event_id))
    if sha256_document(sorted(ids))!=snapshot['selected_id_set_sha256']:raise ValueError('Selected evidence ID hash mismatch')
    return start,end,data


def trial_features(trial,snapshot,policy):
    start,end,data=decoded_snapshot(snapshot,trial)
    def build(a,b,rows):
        return build_profile_document(image_digest=trial['image']['reference'],start_at=a,end_at=b,
            window_seconds=policy['window_seconds'],process_events=rows['process'],runtime_events=rows['runtime'],
            minimum_process_events=policy['minimum_process_events'],minimum_nonempty_windows=policy['minimum_nonempty_windows'])[0]
    windows=[];at=start
    while at<end:
        stop=min(end,at+timedelta(seconds=policy['window_seconds']))
        rows={key:[row for row in values if epoch_ns(at)<=row.time_nano<epoch_ns(stop)] for key,values in data.items()}
        windows.append({'features':build(at,stop,rows),'rows':rows,'start':at,'end':stop});at=stop
    result={'features':build(start,end,data),'windows':windows,'data':data,'image_digest':trial['image']['reference'],
        'identity':(trial.get('workload_id'),trial['image']['reference'],trial.get('runtime_context_hash')),
        'process_events':len(data['process']),'nonempty_windows':sum(bool(row['rows']['process'] or row['rows']['runtime']) for row in windows)}
    if trial.get('ground_truth_class')=='controlled-positive':
        truth=trial.get('ground_truth',{})
        try:
            horizon_start=datetime.fromisoformat(truth['action_started_at_utc'])
            horizon_end=horizon_start+timedelta(seconds=policy['scenario_horizon_seconds'])
            if horizon_start.tzinfo is None or not start<=horizon_start<horizon_end<=end:raise ValueError('Incomplete scenario horizon')
            qualification=[]
            for window in windows:
                a=max(window['start'],horizon_start);b=min(window['end'],horizon_end)
                if a>=b:continue
                rows={key:[row for row in values if epoch_ns(a)<=row.time_nano<epoch_ns(b)] for key,values in data.items()}
                qualification.append({'features':build(a,b,rows),'rows':rows,'start':a,'end':b})
            result['qualification_windows']=qualification
            result['qualification_data']={key:[row for row in values if epoch_ns(horizon_start)<=row.time_nano<epoch_ns(horizon_end)] for key,values in data.items()}
            result['scenario_horizon']={'start':horizon_start.isoformat(),'end':horizon_end.isoformat()}
        except (ValueError,KeyError,TypeError):result['scenario_horizon_unavailable']=True
    return result


def pooled_profile(records):
    categories=defaultdict(Counter);sets=defaultdict(set);numeric=defaultdict(list);transitions=defaultdict(Counter)
    for record in records:
        features=record['features']
        for family,values in features['categorical_distributions'].items():
            count=len(record['data']['runtime']) if family=='runtime_action' else max(0,len(record['data']['process'])-1) if family=='process_sequence_bigram' else len(record['data']['process'])
            categories[family].update({token:weight*count for token,weight in values.items()})
        for family,values in features['observed_sets'].items():sets[family].update(values)
        for window in record['windows']:
            for family,summary in window['features']['numeric_summaries'].items():numeric[family].append(summary['mean'])
        ordered=record['data']['process']
        for left,right in zip(ordered,ordered[1:]):transitions[left.executable or left.process_name or '<unknown>'][right.executable or right.process_name or '<unknown>']+=1
    profile={'schema_version':'porygon.behaviour.v1','categorical_distributions':{},'observed_sets':{key:sorted(values) for key,values in sets.items()},'numeric_summaries':{key:_summary(values) for key,values in numeric.items()}}
    for family,counts in categories.items():
        total=sum(counts.values());profile['categorical_distributions'][family]={key:value/total for key,value in sorted(counts.items())} if total else {}
    return profile,numeric,transitions


def components(window,profile,numeric,transitions):
    observed=window['features']['categorical_distributions'];reference=profile['categorical_distributions']
    distances=[hellinger_distance(reference.get(name,{}),values) for name,values in observed.items() if name!='process_sequence_bigram']
    distances=[value for value in distances if value is not None]
    novelties=[novelty_mass(reference.get(name,{}),values)['score'] for name,values in observed.items() if values]
    ordered=window['rows']['process'];pairs=[(left.executable or left.process_name or '<unknown>',right.executable or right.process_name or '<unknown>') for left,right in zip(ordered,ordered[1:])]
    sequence=markov_surprisal(transitions,pairs)['score']
    tails=[]
    for name,summary in window['features']['numeric_summaries'].items():
        fit=numeric.get(name,[]);value=summary['mean']
        if fit:
            p=min(1,2*min((1+sum(x>=value for x in fit))/(len(fit)+1),(1+sum(x<=value for x in fit))/(len(fit)+1)))
            tails.append(1-p)
    return {'categorical_shift':statistics.mean(distances) if distances else None,'novelty_mass':statistics.mean(novelties) if novelties else None,
        'sequence_surprisal':sequence,'numeric_tail':statistics.mean(tails) if tails else None}


def score_comparators(reference,calibration,observation,policy):
    if observation.get('scenario_horizon_unavailable'):
        return {name:{'status':'insufficient_data','positive':None,'reason':'complete frozen scenario horizon unavailable'} for name in (*DETECTORS,*ABLATIONS)}
    profile,numeric,transitions=pooled_profile(reference)
    fit_values=[components(window,profile,numeric,transitions) for record in reference for window in record['windows']]
    def window_rank(window,names):
        raw=components(window,profile,numeric,transitions);ranks=[]
        for name in names:
            support=[row[name] for row in fit_values if row[name] is not None]
            if raw[name] is None or not support:return None
            ranks.append(1-empirical_upper_tail_pvalue(support,raw[name])['p_value'])
        return statistics.mean(ranks)
    selections={'DET-NOVELTY':('novelty_mass',),'DET-FREQUENCY':('categorical_shift',),'DET-SEQUENCE':('sequence_surprisal',),
        'DET-CALIBRATED':COMPONENTS,'DET-HYBRID':COMPONENTS,
        'ABL-NO-SEQUENCE':tuple(name for name in COMPONENTS if name!='sequence_surprisal'),
        'ABL-NO-NOVELTY':tuple(name for name in COMPONENTS if name!='novelty_mass'),
        'ABL-NO-DISTRIBUTION':tuple(name for name in COMPONENTS if name!='categorical_shift'),
        'ABL-NO-NUMERIC':tuple(name for name in COMPONENTS if name!='numeric_tail')}
    qualifying=observation.get('qualification_data',observation['data'])
    process=qualifying['process'];runtime=qualifying['runtime']
    rules_available=all(getattr(row,'rules_projection_available',False) for row in process)
    rules=False
    if rules_available:
        result=evaluate_detection(anomaly_score=SimpleNamespace(status='scored',total_score=0.0),profile=SimpleNamespace(features=profile,image_digest=observation['image_digest']),process_events=process,runtime_events=runtime)
        rules=any(row['incident_eligible'] and row['rule_id']!='POR-DET-001' for row in result['matches'])
    output={'DET-RULES':{'status':'scored' if rules_available else 'insufficient_data','positive':rules if rules_available else None}}
    for detector,names in selections.items():
        blocks=[]
        for record in [*calibration,observation]:
            values=[window_rank(window,names) for window in record.get('qualification_windows',record['windows'])]
            blocks.append(max(values) if values and all(value is not None for value in values) else None)
        if any(value is None for value in blocks):output[detector]={'status':'insufficient_data','positive':None};continue
        p=empirical_upper_tail_pvalue(blocks[:-1],blocks[-1])['p_value']
        positive=p<=policy['alpha']
        if detector=='DET-HYBRID' or detector.startswith('ABL-'):
            if not rules_available:output[detector]={'status':'insufficient_data','positive':None};continue
            positive=positive or rules
        output[detector]={'status':'scored','positive':positive,'p_value':p,'calibration_runs':len(calibration),'scenario_horizon':observation.get('scenario_horizon')}
    return output


def evaluate_trials(trials,snapshots,assignments,policy):
    validate_policy(policy)
    if len(assignments)!=len(set(assignments)):raise ValueError('Duplicate assignment IDs')
    records={};failures={}
    for trial in trials:
        identifier=trial['trial_id']
        if identifier not in assignments:raise ValueError('Unassigned trial')
        if trial.get('status')!='completed':failures[identifier]='collection_failed';continue
        if identifier not in snapshots:failures[identifier]='snapshot_unavailable';continue
        try:records[identifier]=trial_features(trial,snapshots[identifier],policy)
        except (ValueError,KeyError,TypeError):failures[identifier]='snapshot_invalid'
    outcomes=[];sensitivity=[]
    for trial in trials:
        identifier=trial['trial_id']
        if assignments[identifier] not in ('test','confirmatory'):continue
        for scope in SCOPES:
            outcome={'trial_id':identifier,'scope':scope,'ground_truth_class':trial.get('ground_truth_class','unavailable'),'stratum':trial.get('stratum',trial.get('workload_id','unavailable')),'workload_id':trial.get('workload_id')}
            if identifier not in records:
                outcomes.append(dict(outcome,status='insufficient_data',reason=failures.get(identifier,'unavailable'),comparators={}));continue
            key=scope_key(trial,scope)
            selected={role:[candidate for candidate in trials if assignments[candidate['trial_id']]==role and candidate.get('ground_truth_class')=='benign' and candidate['trial_id'] in records and scope_key(candidate,scope)==key] for role in ('fit','calibration')}
            supported=all(len(selected[role])>=policy['minimum_'+role+'_runs'] and len({row['container_id'] for row in selected[role]})>=policy['minimum_replicas'] for role in selected)
            supported=supported and all(records[row['trial_id']]['process_events']>=policy['minimum_process_events'] and records[row['trial_id']]['nonempty_windows']>=policy['minimum_nonempty_windows'] for row in selected['fit'])
            if not supported:
                outcomes.append(dict(outcome,status='insufficient_data',reason='independent_clean_profile_support',comparators={}));continue
            comparators=score_comparators([records[row['trial_id']] for row in selected['fit']],[records[row['trial_id']] for row in selected['calibration']],records[identifier],policy)
            identities={records[row['trial_id']].get('identity') for row in selected['fit']+selected['calibration']}
            observed_identity=records[identifier].get('identity')
            calibration_status={'status':'drift_detected','covered':None}
            if observed_identity is not None and identities=={observed_identity}:
                calibrated=comparators.get('DET-CALIBRATED',{})
                calibration_status={'status':'calibrated','covered':calibrated['p_value']>policy['alpha']} if calibrated.get('status')=='scored' else {'status':'insufficient_profile','covered':None}
            outcome['calibration_coverage']=calibration_status
            outcomes.append(dict(outcome,status='analysed',fit_runs=[row['trial_id'] for row in selected['fit']],calibration_runs=[row['trial_id'] for row in selected['calibration']],comparators=comparators))
            if scope=='ARM-CONTEXT':
                # Separate copied-fit sensitivity arms. Primary references never mutate.
                poisons=[candidate for candidate in trials if assignments[candidate['trial_id']]=='fit' and candidate.get('ground_truth_class')=='controlled-positive' and candidate['trial_id'] in records and scope_key(candidate,scope)==key]
                for fraction in (0.01,0.05,0.10):
                    needed=math.ceil(len(selected['fit'])*fraction/(1-fraction))
                    entry={'trial_id':identifier,'scenario':'SCN-POISON','requested_fraction':fraction,'injected_runs':needed}
                    if len(poisons)<needed:sensitivity.append(dict(entry,status='insufficient_data',reason='independent_labelled_fit_injection_unavailable'));continue
                    copied=[records[row['trial_id']] for row in selected['fit']]+[records[row['trial_id']] for row in sorted(poisons,key=lambda row:row['trial_id'])[:needed]]
                    sensitivity.append(dict(entry,status='analysed',actual_fraction=needed/len(copied),comparators=score_comparators(copied,[records[row['trial_id']] for row in selected['calibration']],records[identifier],policy)))
                wrong=[candidate for candidate in trials if assignments[candidate['trial_id']]=='fit' and candidate.get('ground_truth_class')=='benign' and candidate['trial_id'] in records and candidate['image']['reference']!=trial['image']['reference']]
                if wrong:
                    wrong_digest=sorted({row['image']['reference'] for row in wrong})[0]
                    wrong=[row for row in wrong if row['image']['reference']==wrong_digest]
                    wrong_cal=[row for row in trials if assignments[row['trial_id']]=='calibration' and row.get('ground_truth_class')=='benign' and row['trial_id'] in records and row['image']['reference']==wrong_digest]
                    if len(wrong)>=policy['minimum_fit_runs'] and len(wrong_cal)>=policy['minimum_calibration_runs']:
                        sensitivity.append({'trial_id':identifier,'scenario':'SCN-CROSS','status':'analysed','misapplied_digest':wrong_digest,'comparators':score_comparators([records[row['trial_id']] for row in wrong],[records[row['trial_id']] for row in wrong_cal],records[identifier],policy)})
                    else:sensitivity.append({'trial_id':identifier,'scenario':'SCN-CROSS','status':'insufficient_data'})
                else:sensitivity.append({'trial_id':identifier,'scenario':'SCN-CROSS','status':'insufficient_data'})

    # Context ablations are explicit extra outcomes, never silently replace main arms.
    by_key={(row['trial_id'],row['scope']):row for row in outcomes}
    for row in outcomes:
        if row['scope']!='ARM-CONTEXT':continue
        digest=by_key.get((row['trial_id'],'ARM-DIGEST'),{});global_row=by_key.get((row['trial_id'],'ARM-GLOBAL'),{})
        row.setdefault('comparators',{})['ABL-NO-CONTEXT']=deepcopy(digest.get('comparators',{}).get('DET-HYBRID',{'status':'insufficient_data','positive':None}))
        fallback={'status':'insufficient_data','positive':None,'selected_scope':None}
        for candidate_scope,candidate in (('ARM-CONTEXT',row),('ARM-DIGEST',digest),('ARM-GLOBAL',global_row)):
            result=candidate.get('comparators',{}).get('DET-HYBRID',{})
            if result.get('status')=='scored':
                fallback=dict(deepcopy(result),selected_scope=candidate_scope);break
        row['comparators']['ABL-FALLBACK']=fallback

    return {'contract':'porygon.frozen-study-analysis','analysis_policy_sha256':sha256_document(policy),'outcomes':outcomes,
        'analysis_only_sensitivity':sensitivity,'planned_test_runs':sum(role in ('test','confirmatory') for role in assignments.values()),'failed_or_missing':failures,
        'unit':'whole independent run','capture_completeness':'unknown','empirical_claims':'require validated measured collection'}
