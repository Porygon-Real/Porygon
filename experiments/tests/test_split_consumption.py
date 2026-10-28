"""Assigned fit/calibration membership wins over chronological ordering."""
from experiments import frozen_analysis as analysis


def policy():
    return {'contract':'porygon.frozen-analysis-policy','implementation':analysis.POLICY_IMPLEMENTATION,
        'window_seconds':60,'minimum_process_events':1,'minimum_nonempty_windows':1,'minimum_fit_runs':10,
        'minimum_calibration_runs':10,'minimum_replicas':3,'scenario_horizon_seconds':60,'alpha':0.05,'missing_component_policy':'abstain',
        'quality_justification':'fixture only','review_reference':'fixture only'}


def test_early_heldout_and_labelled_fit_attack_never_enter_primary_reference(monkeypatch):
    trials=[];assignments={};seen=[]
    for split in ('fit','calibration'):
        for index in range(10):
            identifier=f'{split}-{index}';assignments[identifier]=split
            trials.append({'trial_id':identifier,'status':'completed','ground_truth_class':'benign','container_id':identifier,
                'image':{'reference':'fixture@sha256:'+'a'*64},'human_tag':'fixture:tag','runtime_context_hash':'ctx'})
    for identifier,split,label in (('earliest-heldout','test','controlled-positive'),('labelled-fit-attack','fit','controlled-positive')):
        assignments[identifier]=split;trials.insert(0,{'trial_id':identifier,'status':'completed','ground_truth_class':label,
            'container_id':identifier,'image':{'reference':'fixture@sha256:'+'a'*64},'human_tag':'fixture:tag','runtime_context_hash':'ctx'})
    monkeypatch.setattr(analysis,'trial_features',lambda trial,snapshot,policy:{'identifier':trial['trial_id'],'process_events':1,'nonempty_windows':1})
    def compare(fit,calibration,observed,policy):
        seen.append(([row['identifier'] for row in fit],[row['identifier'] for row in calibration]))
        return {'DET-CALIBRATED':{'status':'scored','positive':False},'DET-HYBRID':{'status':'scored','positive':False}}
    monkeypatch.setattr(analysis,'score_comparators',compare)
    analysis.evaluate_trials(trials,{row['trial_id']:{} for row in trials},assignments,policy())
    assert seen
    for fit,calibration in seen[:4]:
        assert set(fit)=={f'fit-{index}' for index in range(10)}
        assert set(calibration)=={f'calibration-{index}' for index in range(10)}


def test_missing_explicit_policy_does_not_mutate_live_profiles(monkeypatch):
    from experiments.study import stage_analysis
    monkeypatch.setattr('experiments.study._post',lambda *args,**kwargs:(_ for _ in ()).throw(AssertionError('live mutation')))
    result=stage_analysis({'trials':[{'trial_id':'test','status':'completed'}],'splits':{'test':'test'}})
    assert result['status']=='insufficient_data' and result['heldout_runs']==['test']
