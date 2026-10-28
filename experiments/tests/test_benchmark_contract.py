import pytest
from experiments.benchmarks.run import validate_samples


def test_measurement_cannot_omit_hardware_or_unknown_loss_boundaries():
    with pytest.raises(ValueError):validate_samples({'contract':'porygon.capacity-measurement','hardware':{},'samples':[{}]})
