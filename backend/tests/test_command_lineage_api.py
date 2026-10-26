"""Exercise both scoring contracts against PostgreSQL in a disposable schema."""

import os
from datetime import timedelta

import pytest
from sqlalchemy.orm import Session

from porygon_api import main
from porygon_api.baseline import COMMAND_LINEAGE_SCHEMA, FEATURE_SCHEMA_VERSION
from porygon_api.schemas import AnomalyScoreComputeIn, BehaviorProfileBuildIn, MLClassifyEventsIn
from test_incident_grouping import engine as _disposable_engine
from test_parent_correlation import _event
from test_command_lineage import START, DIGEST


engine = _disposable_engine  # Register the shared disposable-schema fixture.


def test_profile_build_scoring_replay_and_repaired_lineage(engine, monkeypatch):
    if os.environ.get("PORYGON_TEST_POSTGRES") != "1":
        pytest.skip("Requires PostgreSQL profile/scoring transaction locks")
    with Session(engine) as db:
        training = []
        for index, second in enumerate((1, 2, 3, 6, 7, 8)):
            record = _event(
                format(index + 1, "064x"), START + timedelta(seconds=second), index + 10
            )
            record.image_digest = DIGEST
            record.container_id = "a" * 64
            record.process_name = "curl"
            record.executable = "/usr/bin/curl"
            record.command_line = "curl --silent https://service/health"
            if index % 3:
                record.parent_event_id = training[-1].event_id
            training.append(record)
        db.add_all(training)
        observed = []
        for index in range(3):
            record = _event(
                format(index + 100, "064x"), START + timedelta(seconds=31 + index), 100 + index
            )
            record.image_digest = DIGEST
            record.container_id = "a" * 64
            record.process_name = "curl"
            record.executable = "/usr/bin/curl"
            record.command_line = "curl --upload-file /tmp/report https://remote/upload"
            observed.append(record)
        db.add_all(observed)
        db.commit()
        profiles = {}
        for schema in (FEATURE_SCHEMA_VERSION, COMMAND_LINEAGE_SCHEMA):
            payload = BehaviorProfileBuildIn(
                image_digest=DIGEST,
                training_start=START,
                training_end=START + timedelta(seconds=10),
                window_seconds=5,
                minimum_process_events=6,
                minimum_nonempty_windows=2,
                approved_by="Anurup R Krishnan",
                feature_schema_version=schema,
            )
            profile = main.build_behavior_profile(payload, db)
            assert profile.quality["passed"]
            assert profile.feature_schema_version == schema
            main.activate_behavior_profile(profile.profile_id, db)
            profiles[schema] = profile
        scores = {}
        for schema, profile in profiles.items():
            payload = AnomalyScoreComputeIn(
                image_digest=DIGEST,
                profile_id=profile.profile_id,
                window_start=START + timedelta(seconds=30),
            )
            score = main.compute_anomaly_score(payload, db)
            assert score.status == "scored"
            assert main.compute_anomaly_score(payload, db).score_id == score.score_id
            assert score.scoring_config["feature_schema_version"] == schema
            scores[schema] = score
        advanced = scores[COMMAND_LINEAGE_SCHEMA]
        assert advanced.algorithm_version == "porygon.distance.command-lineage"
        assert advanced.total_score > scores[FEATURE_SCHEMA_VERSION].total_score
        assert (
            advanced.components["categorical_distance"]["families"]["command_shape"]["distance"] > 0
        )
        assert "ml_threat_classification" not in advanced.explanation
        assert advanced.explanation["ml_input_contract"]["supported"] is False
        captured = []
        predict = main.default_classifier.predict_events

        def capture(events, baseline_features=None, drift_score=None):
            captured.append((baseline_features, drift_score))
            return predict(events, baseline_features=baseline_features, drift_score=drift_score)

        monkeypatch.setattr(main.default_classifier, "predict_events", capture)
        main.classify_events(MLClassifyEventsIn(image_digest=DIGEST), db)
        assert captured[-1][1] == scores[FEATURE_SCHEMA_VERSION].total_score
        main.classify_container("a" * 64, event_limit=50, db=db)
        assert captured[-1][1] == scores[FEATURE_SCHEMA_VERSION].total_score
        assert captured[-1][0] == profiles[FEATURE_SCHEMA_VERSION].features
        # A repaired parent link changes feature content while event IDs stay the same.
        observed[1].parent_event_id = observed[0].event_id
        db.commit()
        payload = AnomalyScoreComputeIn(
            image_digest=DIGEST,
            profile_id=profiles[COMMAND_LINEAGE_SCHEMA].profile_id,
            window_start=START + timedelta(seconds=30),
        )
        repaired = main.compute_anomaly_score(payload, db)
        assert repaired.score_id != advanced.score_id
        assert (
            repaired.observation_manifest["selected_event_ids_sha256"]
            == advanced.observation_manifest["selected_event_ids_sha256"]
        )
        assert repaired.observation_manifest["observation_coverage"]["verified_lineage_edges"] == 1
        for index in range(3):
            record = _event(
                format(index + 200, "064x"), START + timedelta(seconds=41 + index), 200 + index
            )
            record.image_digest = DIGEST
            record.command_line = None
            db.add(record)
        db.commit()
        missing = main.compute_anomaly_score(
            AnomalyScoreComputeIn(
                image_digest=DIGEST,
                profile_id=profiles[COMMAND_LINEAGE_SCHEMA].profile_id,
                window_start=START + timedelta(seconds=40),
            ),
            db,
        )
        assert missing.status == "insufficient_data"
        assert missing.total_score is None
        assert missing.components["reason"] == "Insufficient command-line evidence coverage"
