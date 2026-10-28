from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
import pytest
from experiments.artifacts import atomic_write_bytes,ArtifactError
from experiments.confirmatory import confined
from experiments.frozen_statistics import summarize


def test_publication_is_atomic_and_never_overwrites_a_completed_artifact(tmp_path):
    barrier=Barrier(2);path=tmp_path/'evidence.json'
    def publish(value):
        barrier.wait()
        try:atomic_write_bytes(path,value);return 'published'
        except ArtifactError:return 'conflict'
    with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(publish,[b'one',b'two']))
    assert sorted(results)==['conflict','published']
    assert path.read_bytes() in (b'one',b'two')


def test_replay_rejects_parent_absolute_and_symlink_paths(tmp_path):
    (tmp_path/'outside').write_text('value');(tmp_path/'link').symlink_to(tmp_path/'outside')
    for name in ('../outside',str(tmp_path/'outside'),'link'):
        with pytest.raises(ArtifactError):confined(tmp_path,name)


def test_missing_outcome_remains_in_denominator_and_blocks_paired_claims():
    report={'outcomes':[{'trial_id':'failed','scope':scope,'ground_truth_class':'benign','comparators':{}} for scope in ('ARM-GLOBAL','ARM-TAG','ARM-DIGEST','ARM-CONTEXT')]}
    result=summarize(report)
    row=next(row for row in result['tables'] if row['scope']=='ARM-CONTEXT' and row['detector']=='DET-HYBRID' and row['ground_truth_class']=='benign')
    assert row['planned_denominator']==1 and row['abstained_or_failed']==1
    assert row['point_rate'] is None and row['lower_detection_rate']==0 and row['upper_detection_rate']==1
    assert all(row['status']=='insufficient_data' for row in result['primary_contrasts'])


def test_paired_interval_handles_no_tie_eight_two_discordant_stratum():
    from experiments.frozen_statistics import paired_interval
    ids=[str(index) for index in range(10)]
    by_id={(identifier,'ARM-CONTEXT'):{'workload_id':'WL-NGX-V1'} for identifier in ids}
    result=paired_interval(ids,[False]*8+[True]*2,[True]*8+[False]*2,by_id,resamples=100)
    assert result['point']==0.6 and -1<=result['lower']<=result['upper']<=1
