from porygon_telemetry.observer import SourceCursor


def test_initial_eof_cursor_never_replays_historical_records(tmp_path):
    path = tmp_path / "events"
    path.write_bytes(b"history\n")
    cursor = SourceCursor()
    assert cursor.read_lines(path, tail_if_new=True) == []
    with path.open("ab") as handle:
        handle.write(b"new\n")
    assert cursor.read_lines(path) == [b"new\n"]
    assert cursor.read_lines(path) == []


def test_partial_record_waits_for_newline_and_truncation_is_explicit(tmp_path):
    path = tmp_path / "events"
    path.write_bytes(b"partial")
    cursor = SourceCursor()
    assert cursor.read_lines(path) == []
    with path.open("ab") as handle:
        handle.write(b" record\n")
    assert cursor.read_lines(path) == [b"partial record\n"]
    path.write_bytes(b"new\n")
    assert cursor.read_lines(path) == [b"new\n"] and cursor.resets == 1
