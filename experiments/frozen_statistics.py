"""Run-level denominators, abstention bounds and exact paired frozen contrasts."""
from dataclasses import asdict
from collections import defaultdict
import random
import math
from experiments.analysis import clopper_pearson_interval,exact_mcnemar_p,holm_adjust
from experiments.frozen_analysis import SCOPES,DETECTORS,ABLATIONS


def paired_interval(ids,left,right,by_id,*,alpha=0.05,resamples=10000,seed=20260823):
    """Resample complete paired outcomes together within workload-version strata."""
    if not ids or len(ids)!=len(left) or len(ids)!=len(right):raise ValueError('Paired run accounting required')
    strata=defaultdict(list)
    for identifier,a,b in zip(ids,left,right):
        version=by_id[(identifier,'ARM-CONTEXT')].get('workload_id')
        if not version:raise ValueError('Workload/version stratum required for paired interval')
        strata[version].append((int(a),int(b)))
    populations=[(len(values),sum(b>a for a,b in values),sum(b<a for a,b in values)) for values in strata.values()]
    rng=random.Random(seed);effects=[]
    for _ in range(resamples):
        total=0
        for count,positive_count,negative_count in populations:
            positive_p=positive_count/count
            # Exact multinomial resampling of paired differences (-1,0,+1).
            # This preserves paired covariance without O(runs*resamples) loops.
            positive=rng.binomialvariate(count,positive_p)
            negative=rng.binomialvariate(count-positive,negative_count/(count-positive_count)) if positive_p<1 else 0
            total+=positive-negative
        effects.append(total/len(ids))
    effects.sort();low=effects[max(0,math.floor(alpha/2*resamples))];high=effects[min(resamples-1,math.ceil((1-alpha/2)*resamples)-1)]
    return {'point':sum(int(b)-int(a) for a,b in zip(left,right))/len(ids),'lower':low,'upper':high,
        'confidence':1-alpha,'independent_pairs':len(ids),'resamples':resamples,'seed':seed,'strata':sorted(strata),'direction':'right minus left'}


def summarize(report):
    rows=report['outcomes'];tables=[]
    for scope in SCOPES:
        selected=[row for row in rows if row['scope']==scope]
        for detector in (*DETECTORS,*ABLATIONS):
            for ground_truth in ('benign','controlled-positive'):
                cohort=[row for row in selected if row['ground_truth_class']==ground_truth]
                decisions=[row.get('comparators',{}).get(detector,{}) for row in cohort]
                known=[row['positive'] for row in decisions if row.get('status')=='scored' and type(row.get('positive')) is bool]
                positives=sum(known);missing=len(cohort)-len(known);n=len(cohort)
                tables.append({'scope':scope,'detector':detector,'ground_truth_class':ground_truth,'planned_denominator':n,
                    'resolved_denominator':len(known),'positive':positives,'abstained_or_failed':missing,
                    'lower_detection_rate':positives/n if n else None,'upper_detection_rate':(positives+missing)/n if n else None,
                    'resolved_conditional_interval':asdict(clopper_pearson_interval(positives,len(known))),
                    'point_rate':positives/n if n and not missing else None})
    by_id={(row['trial_id'],row['scope']):row for row in rows};pairs=[]
    benign=sorted({row['trial_id'] for row in rows if row['ground_truth_class']=='benign'})
    positives=sorted({row['trial_id'] for row in rows if row['ground_truth_class']=='controlled-positive'})
    def decisions(ids,scope,detector):
        output=[]
        for identifier in ids:
            value=by_id.get((identifier,scope),{}).get('comparators',{}).get(detector,{})
            if value.get('status')!='scored' or type(value.get('positive')) is not bool:return None
            output.append(value['positive'])
        return output
    raw={};prepared={}
    for simpler in SCOPES[:-1]:
        identifier='CONTEXT_vs_'+simpler
        left=decisions(benign,simpler,'DET-CALIBRATED');right=decisions(benign,'ARM-CONTEXT','DET-CALIBRATED')
        recall_left=decisions(positives,simpler,'DET-CALIBRATED');recall_right=decisions(positives,'ARM-CONTEXT','DET-CALIBRATED')
        if any(value is None for value in (left,right,recall_left,recall_right)) or not benign or not positives:
            pairs.append({'contrast':identifier,'status':'insufficient_data','reason':'paired whole-run outcomes include missingness; no complete-case substitution'});continue
        test=exact_mcnemar_p(contrast_id=identifier,arm_a_positive=left,arm_b_positive=right)
        raw[identifier]=test.p_value;prepared[identifier]=(left,right,recall_left,recall_right,test)
    if len(raw)==3:
        adjusted={row.contrast_id:row.adjusted_p for row in holm_adjust(raw)}
        for identifier,(left,right,recall_left,recall_right,test) in prepared.items():
            fpr=paired_interval(benign,right,left,by_id,alpha=0.05/3)
            recall=paired_interval(positives,recall_left,recall_right,by_id)
            coarse=sum(left)/len(left);fine=sum(right)/len(right)
            relative=(coarse-fine)/coarse if coarse else None
            context_rows=[row for row in rows if row['scope']=='ARM-CONTEXT']
            fragmentation=sum(row.get('status')!='analysed' for row in context_rows)/len(context_rows) if context_rows else 1
            decision={'h1_supported':bool(relative is not None and relative>=0.25 and adjusted[identifier]<0.05 and fpr['lower']>0 and recall['lower']>=-0.05 and fragmentation<=0.10),
                'material_relative_fpr_reduction':relative,'paired_fpr_interval_excludes_zero':fpr['lower']>0,
                'recall_non_inferior':recall['lower']>=-0.05,'context_fragmentation':fragmentation,
                'criteria':'point relative FPR reduction >=25%, Holm p<.05, simultaneous paired FPR benefit interval >0, paired recall difference lower >=-.05, fragmentation <=.10'}
            pairs.append({'contrast':identifier,'status':'analysed','mcnemar':asdict(test),'holm_adjusted_p':adjusted[identifier],
                'fpr_paired_effect':fpr,'recall_paired_effect':recall,'decision':decision})
    elif prepared:
        for identifier in prepared:pairs.append({'contrast':identifier,'status':'insufficient_data','reason':'complete co-primary Holm family unavailable'})
    secondary=[]
    # Families are fixed by this source/policy hash before collection. Each
    # detector or ablation family includes both FPR and recall paired tests.
    for family,alternatives in (('detector',tuple(name for name in DETECTORS if name!='DET-HYBRID')),('ablation',ABLATIONS)):
        computed={};effects={};unavailable=[]
        for endpoint,ids in (('benign-fpr',benign),('controlled-recall',positives)):
            for alternative in alternatives:
                identifier=family+':'+endpoint+':DET-HYBRID_vs_'+alternative
                baseline=decisions(ids,'ARM-CONTEXT','DET-HYBRID');other=decisions(ids,'ARM-CONTEXT',alternative)
                if not ids or baseline is None or other is None:
                    unavailable.append(identifier);continue
                computed[identifier]=exact_mcnemar_p(contrast_id=identifier,arm_a_positive=baseline,arm_b_positive=other)
                effects[identifier]=(ids,baseline,other)
        if unavailable:
            secondary.extend({'family':family,'contrast':identifier,'status':'insufficient_data','reason':'predeclared family includes missing paired outcomes'} for identifier in (*computed,*unavailable))
        else:
            correction={row.contrast_id:row.adjusted_p for row in holm_adjust({key:value.p_value for key,value in computed.items()})}
            secondary.extend({'family':family,'contrast':identifier,'status':'analysed','mcnemar':asdict(value),'holm_adjusted_p':correction[identifier],
                'paired_effect':paired_interval(*effects[identifier],by_id,alpha=0.05/len(computed))} for identifier,value in computed.items())
    calibration=[]
    for scope in SCOPES:
        benign_rows=[row for row in rows if row['scope']==scope and row['ground_truth_class']=='benign']
        counts=defaultdict(int);covered=0;eligible=0
        for row in benign_rows:
            value=row.get('calibration_coverage',{'status':'insufficient_profile','covered':None})
            counts[value['status']]+=1
            if value['status']=='calibrated':eligible+=1;covered+=value['covered'] is True
        calibration.append({'scope':scope,'planned_denominator':len(benign_rows),'same_identity_denominator':eligible,
            'covered':covered,'coverage_same_identity':covered/eligible if eligible else None,'statuses':dict(counts),
            'interval_same_identity':asdict(clopper_pearson_interval(covered,eligible)),'nominal':0.95,
            'within_declared_tolerance':0.92<=covered/eligible<=0.98 if eligible else None})
    return {'contract':'porygon.frozen-result-tables','unit':'whole independent run','tables':tables,'primary_contrasts':pairs,'secondary_contrast_families':secondary,'calibration_coverage':calibration,
        'prevalence_interpretation':'controlled study prevalence; not deployment precision','missingness_policy':'all planned trials retained with explicit rate bounds'}
