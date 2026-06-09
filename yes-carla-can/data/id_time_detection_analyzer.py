import argparse
import csv
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from collections import deque
import math

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from defense.id_time_intrusion_detection import IdTimeIntrusionDetection
from can_bus_data_analyzer import read_capture, normalize_can_id


DEFAULT_BASELINE = PROJECT_ROOT / "data" / "candump-2026-04-17_225932_parsed_statistics.json"


class _QueueStats:
    def __init__(self, maxlen=10):
        self.queue = deque(maxlen=maxlen)
        self._sum = 0
        self._sum_sq = 0

    def add(self, value):
        if len(self.queue) == self.queue.maxlen:
            old_value = self.queue[0]
            self._sum -= old_value
            self._sum_sq -= old_value * old_value
        self.queue.append(value)
        self._sum += value
        self._sum_sq += value * value

    def std(self):
        if len(self.queue) < 2:
            return 0
        n = len(self.queue)
        mean = self._sum / n
        variance = (self._sum_sq / n) - (mean * mean)
        return math.sqrt(max(0, variance))

    def __len__(self):
        return len(self.queue)


class OriginalIdTimeIntrusionDetection:
    """Original id_time behavior kept for offline before/after comparison."""

    def __init__(self):
        self.intrusion_counter = {}
        self.regular_counter = 0

    def load(self, path):
        with open(path, "r") as file:
            can_ids_statistics = json.load(file)

        self.known_ids = list(can_ids_statistics.keys())
        self.can_ids_statistics = can_ids_statistics
        self.running_statistics = {}

    def run(self, message):
        can_id = str(hex(message.arbitration_id))
        timestamp = message.timestamp

        if can_id not in self.known_ids:
            self.intrusion_counter[can_id] = self.intrusion_counter.get(can_id, 0) + 1
            return

        if self.can_ids_statistics[can_id]["msg_type"] == "periodic":
            if can_id not in self.running_statistics:
                self.running_statistics[can_id] = {"last_timestamps": _QueueStats(maxlen=10)}
                self.running_statistics[can_id]["last_timestamps"].add(timestamp)
            else:
                self.running_statistics[can_id]["last_timestamps"].add(timestamp)

            stats = self.running_statistics[can_id]["last_timestamps"]
            if len(stats) == stats.queue.maxlen:
                expected_std = 3 * self.can_ids_statistics[can_id]["std_timestamp_diff"]
                actual_std = stats.std()
                stats.add(timestamp)

                if actual_std > expected_std:
                    self.intrusion_counter[can_id] = self.intrusion_counter.get(can_id, 0) + 1
                    return

        self.regular_counter += 1


def _format_can_id(can_id):
    text = str(can_id)
    if text.lower().startswith("0x"):
        return f"0x{text[2:].upper()}"
    if text:
        return f"0x{text.upper()}"
    return ""


def _run_detector(capture_path, baseline_path, detector_cls=IdTimeIntrusionDetection):
    try:
        detector = detector_cls(verbose=False)
    except TypeError:
        detector = detector_cls()
    detector.load(baseline_path)

    rows = read_capture(capture_path)
    for row in rows:
        detector.run(
            SimpleNamespace(
                arbitration_id=int(normalize_can_id(row["can_id"]), 16),
                timestamp=row["timestamp"],
            )
        )

    return {
        "capture": str(capture_path),
        "messages": len(rows),
        "regular_messages": detector.regular_counter,
        "intrusions_by_id": detector.intrusion_counter,
        "total_intrusions": sum(detector.intrusion_counter.values()),
    }


def _write_csv(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["scenario", "capture", "messages", "regular_messages", "can_id", "intrusions"]
    with path.open("w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        for scenario, result in rows.items():
            if result["intrusions_by_id"]:
                for can_id, count in sorted(result["intrusions_by_id"].items()):
                    writer.writerow(
                        {
                            "scenario": scenario,
                            "capture": result["capture"],
                            "messages": result["messages"],
                            "regular_messages": result["regular_messages"],
                            "can_id": _format_can_id(can_id),
                            "intrusions": count,
                        }
                    )
            else:
                writer.writerow(
                    {
                        "scenario": scenario,
                        "capture": result["capture"],
                        "messages": result["messages"],
                        "regular_messages": result["regular_messages"],
                        "can_id": "",
                        "intrusions": 0,
                    }
                )


def _write_plot(path, results, title="id_time intrusion detections by scenario"):
    try:
        import matplotlib.pyplot as plt
    except ImportError:
        print("[WARN] matplotlib is not installed; skipping plot.")
        return

    path.parent.mkdir(parents=True, exist_ok=True)
    scenarios = ["normal", "attack"]
    values = [results[scenario]["total_intrusions"] for scenario in scenarios]

    fig, ax = plt.subplots(figsize=(7, 4))
    ax.bar(scenarios, values, color=["#4C78A8", "#E45756"])
    ax.set_ylabel("IDS alerts")
    ax.set_xlabel("Scenario")
    ax.set_title(title)
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


def _build_results(normal_path, attack_path, baseline_path, detector_cls):
    results = {
        "normal": _run_detector(normal_path, baseline_path, detector_cls),
        "attack": _run_detector(attack_path, baseline_path, detector_cls),
    }
    false_positive_rate = (
        results["normal"]["total_intrusions"] / results["normal"]["messages"]
        if results["normal"]["messages"]
        else 0.0
    )
    results["summary"] = {
        "false_positive_rate": false_positive_rate,
        "attack_intrusions": results["attack"]["total_intrusions"],
    }
    return results


def main():
    parser = argparse.ArgumentParser(description="Evaluate id_time IDS over captured CAN logs.")
    parser.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    parser.add_argument("--normal", type=Path, required=True)
    parser.add_argument("--attack", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=PROJECT_ROOT / "data" / "etapa5_detection")
    parser.add_argument("--plots", action="store_true")
    parser.add_argument(
        "--compare-versions",
        action="store_true",
        help="Also evaluate the original detector behavior and write before/after outputs.",
    )
    args = parser.parse_args()

    results = _build_results(args.normal, args.attack, args.baseline, IdTimeIntrusionDetection)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    json_path = args.output_dir / "id_time_detection_results.json"
    csv_path = args.output_dir / "id_time_detection_results.csv"
    json_path.write_text(json.dumps(results, indent=4))
    _write_csv(csv_path, {"normal": results["normal"], "attack": results["attack"]})
    if args.plots:
        _write_plot(
            args.output_dir / "id_time_detection_counts.png",
            results,
            "id_time improved detector",
        )

    if args.compare_versions:
        original_results = _build_results(
            args.normal,
            args.attack,
            args.baseline,
            OriginalIdTimeIntrusionDetection,
        )
        combined_results = {
            "original": original_results,
            "improved": results,
        }
        (args.output_dir / "id_time_detection_versions.json").write_text(
            json.dumps(combined_results, indent=4)
        )
        _write_csv(
            args.output_dir / "id_time_detection_original_results.csv",
            {"normal": original_results["normal"], "attack": original_results["attack"]},
        )
        _write_csv(
            args.output_dir / "id_time_detection_improved_results.csv",
            {"normal": results["normal"], "attack": results["attack"]},
        )
        if args.plots:
            _write_plot(
                args.output_dir / "id_time_detection_counts_original.png",
                original_results,
                "id_time original detector",
            )
            _write_plot(
                args.output_dir / "id_time_detection_counts_improved.png",
                results,
                "id_time improved detector",
            )

    print(json.dumps(results, indent=4))
    print(f"Etapa 5 IDS analysis written to {args.output_dir}")


if __name__ == "__main__":
    main()
