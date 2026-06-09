import json
from types import SimpleNamespace

from defense.id_time_intrusion_detection import IdTimeIntrusionDetection


def _write_baseline(tmp_path):
    baseline = {
        "604": {
            "mean_timestamp_diff": 0.2,
            "std_timestamp_diff": 0.005,
            "msg_type": "periodic",
        }
    }
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps(baseline))
    return path


def _message(can_id, timestamp):
    return SimpleNamespace(arbitration_id=can_id, timestamp=timestamp)


def test_known_id_is_not_reported_as_unknown(tmp_path):
    detector = IdTimeIntrusionDetection(verbose=False)
    detector.load(_write_baseline(tmp_path))

    detector.run(_message(0x604, 1.0))

    assert detector.intrusion_counter == {}
    assert detector.regular_counter == 1


def test_normal_periodic_traffic_does_not_trigger_false_positive(tmp_path):
    detector = IdTimeIntrusionDetection(verbose=False)
    detector.load(_write_baseline(tmp_path))

    for i in range(12):
        detector.run(_message(0x604, 1.0 + i * 0.2))

    assert detector.intrusion_counter == {}
    assert detector.regular_counter == 12


def test_fast_periodic_spoofing_triggers_timing_detection(tmp_path):
    detector = IdTimeIntrusionDetection(verbose=False)
    detector.load(_write_baseline(tmp_path))

    for i in range(12):
        detector.run(_message(0x604, 1.0 + i * 0.05))

    assert detector.intrusion_counter["604"] > 0
