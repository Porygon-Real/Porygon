from __future__ import annotations

import sys

from scripts import porygon_baseline, porygon_score


def test_baseline_cli_selects_support_aware_schema_and_keeps_legacy_default(monkeypatch, capsys):
    captured = {}
    monkeypatch.setattr(porygon_baseline, "_token", lambda: "synthetic-test-token")
    monkeypatch.setattr(
        porygon_baseline,
        "_request",
        lambda method, url, token=None, payload=None: captured.update(payload=payload) or {"ok": True},
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "porygon_baseline.py",
            "build",
            "--image-digest",
            "example/app@sha256:" + "a" * 64,
            "--start",
            "2026-11-01T00:00:00+00:00",
            "--end",
            "2026-11-01T00:10:00+00:00",
            "--approved-by",
            "operator",
            "--feature-schema",
            "porygon.behaviour.support-aware",
        ],
    )

    assert porygon_baseline.main() == 0
    capsys.readouterr()
    assert captured["payload"]["feature_schema_version"] == "porygon.behaviour.support-aware"

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "porygon_baseline.py",
            "build",
            "--image-digest",
            "example/app@sha256:" + "a" * 64,
            "--start",
            "2026-11-01T00:00:00+00:00",
            "--end",
            "2026-11-01T00:10:00+00:00",
            "--approved-by",
            "operator",
        ],
    )
    assert porygon_baseline.main() == 0
    capsys.readouterr()
    assert captured["payload"]["feature_schema_version"] == "porygon.behaviour.v1"


def test_score_cli_selects_support_aware_algorithm(monkeypatch, capsys):
    captured = {}
    monkeypatch.setattr(porygon_score, "_token", lambda: "synthetic-test-token")
    monkeypatch.setattr(
        porygon_score,
        "_request",
        lambda method, url, token=None, payload=None: captured.update(payload=payload) or {"ok": True},
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "porygon_score.py",
            "compute",
            "--image-digest",
            "example/app@sha256:" + "b" * 64,
            "--window-start",
            "2026-11-01T00:00:00+00:00",
            "--algorithm",
            "porygon.distance.support-aware",
        ],
    )

    assert porygon_score.main() == 0
    capsys.readouterr()
    assert captured["payload"]["algorithm_version"] == "porygon.distance.support-aware"
