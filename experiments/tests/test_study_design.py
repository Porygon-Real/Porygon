from copy import deepcopy
import json
from pathlib import Path
import pytest
from experiments.validate_study_plan import validate
ROOT=Path(__file__).resolve().parents[2]


def proposal():return json.loads((ROOT/'experiments/protocols/runtime-evidence-study.json').read_text())


def test_design_can_be_valid_while_collection_stays_blocked():
    result=validate(proposal(),check_sources=True)
    assert result['design_valid'] and not result['collection_ready']
    with pytest.raises(ValueError):validate(proposal(),for_collection=True)


def test_same_physical_group_cannot_cross_splits():
    value=proposal();row={'run_id':'fit','family':'nginx','release':'a','host_id':'host','day':'2027-01-01','split':'fit','label_source':'independent-controller'}
    other=deepcopy(row);other.update(run_id='test',split='test');value['runs']=[row,other]
    with pytest.raises(ValueError,match='Physical'):validate(value)
