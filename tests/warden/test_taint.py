import pytest

from warden.broker.taint import TaintTracker


def test_a_fresh_task_is_clean():
    tracker = TaintTracker()
    assert tracker.snapshot("4711") == {
        "data_classes_held": [],
        "rows_returned_so_far": 0,
    }


def test_reading_pii_taints_the_task():
    tracker = TaintTracker()
    tracker.record_read("4711", data_class="pii", rows=1)
    assert tracker.snapshot("4711")["data_classes_held"] == ["pii"]


def test_taint_is_sticky_across_later_clean_reads():
    tracker = TaintTracker()
    tracker.record_read("4711", data_class="pii", rows=1)
    tracker.record_read("4711", data_class=None, rows=0)
    tracker.record_read("4711", data_class="public", rows=0)
    assert "pii" in tracker.snapshot("4711")["data_classes_held"]


def test_rows_accumulate_across_calls():
    tracker = TaintTracker()
    for _ in range(50):
        tracker.record_read("4711", data_class="pii", rows=1)
    assert tracker.snapshot("4711")["rows_returned_so_far"] == 50


def test_tasks_are_isolated_from_each_other():
    tracker = TaintTracker()
    tracker.record_read("4711", data_class="pii", rows=10)
    assert tracker.snapshot("9999") == {
        "data_classes_held": [],
        "rows_returned_so_far": 0,
    }


def test_data_classes_are_sorted_and_deduplicated():
    tracker = TaintTracker()
    tracker.record_read("4711", data_class="pii", rows=1)
    tracker.record_read("4711", data_class="internal", rows=1)
    tracker.record_read("4711", data_class="pii", rows=1)
    assert tracker.snapshot("4711")["data_classes_held"] == ["internal", "pii"]


def test_negative_rows_are_rejected():
    tracker = TaintTracker()
    with pytest.raises(ValueError):
        tracker.record_read("4711", data_class="pii", rows=-5000000)
    assert tracker.snapshot("4711")["rows_returned_so_far"] == 0


def test_snapshot_is_not_a_live_view_of_internal_state():
    tracker = TaintTracker()
    tracker.record_read("4711", data_class="pii", rows=1)
    snap = tracker.snapshot("4711")
    snap["data_classes_held"].append("exfiltrated")
    snap["rows_returned_so_far"] = 999999
    fresh = tracker.snapshot("4711")
    assert fresh["data_classes_held"] == ["pii"]
    assert fresh["rows_returned_so_far"] == 1
