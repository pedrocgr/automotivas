import pytest

from data.can_bus_data_analyzer import (
    compare_statistics,
    compute_statistics,
    normalize_can_id,
    read_capture,
)


def test_normalize_can_id_strips_prefix_and_uppercases():
    assert normalize_can_id("0x60d") == "60D"
    assert normalize_can_id("710") == "710"


def test_read_capture_parses_raw_candump_log(tmp_path):
    log = tmp_path / "capture.log"
    log.write_text(
        "(1776477572.309063) vcan0 710#00000000\n"
        "(1776477572.359063) vcan0 604#01\n"
    )

    df = read_capture(log)

    assert [row["can_id"] for row in df] == ["710", "604"]
    assert [row["payload"] for row in df] == ["00000000", "01"]


def test_compute_statistics_counts_and_periods(tmp_path):
    log = tmp_path / "capture.log"
    log.write_text(
        "(1.000000) vcan0 710#00000000\n"
        "(1.050000) vcan0 710#00000000\n"
        "(1.100000) vcan0 710#00000000\n"
        "(1.200000) vcan0 604#00\n"
    )

    stats = compute_statistics(read_capture(log))

    assert stats["710"]["count"] == 3
    assert stats["710"]["mean_timestamp_diff"] == pytest.approx(0.05)
    assert stats["710"]["rate_msg_s"] == pytest.approx(30.0)
    assert stats["604"]["count"] == 1


def test_compare_statistics_reports_deltas():
    normal = {
        "604": {"count": 10, "rate_msg_s": 5.0, "mean_timestamp_diff": 0.2},
    }
    attack = {
        "604": {"count": 110, "rate_msg_s": 55.0, "mean_timestamp_diff": 0.01},
    }

    comparison = compare_statistics(normal, attack)

    assert comparison["604"]["count_delta"] == 100
    assert comparison["604"]["rate_delta_msg_s"] == pytest.approx(50.0)
    assert comparison["604"]["mean_period_delta_s"] == pytest.approx(-0.19)
