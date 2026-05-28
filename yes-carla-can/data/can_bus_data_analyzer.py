import argparse
import csv
import json
import statistics
from collections import defaultdict
from pathlib import Path


def normalize_can_id(can_id):
    """Return a stable uppercase hexadecimal CAN ID without the 0x prefix."""
    text = str(can_id).strip()
    if text.lower().startswith("0x"):
        text = text[2:]
    return text.upper()


def read_capture(path):
    """Read either a parsed candump CSV or a raw candump .log file."""
    path = Path(path)
    rows = []
    if path.suffix.lower() == ".csv":
        with path.open("r", newline="") as file:
            reader = csv.DictReader(file)
            required_columns = {"timestamp", "can_id"}
            missing_columns = required_columns - set(reader.fieldnames or [])
            if missing_columns:
                raise ValueError(f"{path} is missing required columns: {sorted(missing_columns)}")
            for row in reader:
                rows.append(row)
    else:
        with path.open("r") as file:
            for line in file:
                parts = line.strip().split()
                if len(parts) < 3 or "#" not in parts[2]:
                    continue
                timestamp = parts[0].replace("(", "").replace(")", "")
                can_id, payload = parts[2].split("#", 1)
                rows.append(
                    {
                        "timestamp": timestamp,
                        "bus": parts[1],
                        "can_id": can_id,
                        "payload": payload,
                    }
                )

    parsed_rows = []
    for row in rows:
        try:
            timestamp = float(row["timestamp"])
        except (KeyError, TypeError, ValueError):
            continue
        can_id = normalize_can_id(row.get("can_id", ""))
        if not can_id:
            continue
        parsed_rows.append(
            {
                "timestamp": timestamp,
                "bus": row.get("bus", ""),
                "can_id": can_id,
                "payload": row.get("payload", ""),
            }
        )

    return sorted(parsed_rows, key=lambda row: row["timestamp"])


def compute_statistics(df):
    """Compute count, message rate and inter-arrival period statistics per CAN ID."""
    stats = {}
    timestamps_by_id = defaultdict(list)
    for row in df:
        timestamps_by_id[row["can_id"]].append(row["timestamp"])

    for can_id in sorted(timestamps_by_id):
        timestamps = sorted(timestamps_by_id[can_id])
        diffs = [right - left for left, right in zip(timestamps, timestamps[1:])]
        duration = float(timestamps[-1] - timestamps[0]) if len(timestamps) > 1 else 0.0
        count = int(len(timestamps))
        mean_diff = float(statistics.mean(diffs)) if diffs else 0.0
        std_diff = float(statistics.stdev(diffs)) if len(diffs) > 1 else 0.0
        msg_type = "periodic" if len(diffs) > 1 and std_diff < 0.01 else "sporadic"
        stats[can_id] = {
            "count": count,
            "duration_s": duration,
            "rate_msg_s": float(count / duration) if duration > 0 else 0.0,
            "mean_timestamp_diff": mean_diff,
            "std_timestamp_diff": std_diff,
            "min_timestamp_diff": float(min(diffs)) if diffs else 0.0,
            "max_timestamp_diff": float(max(diffs)) if diffs else 0.0,
            "msg_type": msg_type,
        }
    return stats


def compare_statistics(normal_stats, attack_stats):
    all_ids = sorted(set(normal_stats) | set(attack_stats))
    comparison = {}
    for can_id in all_ids:
        normal = normal_stats.get(can_id, {})
        attack = attack_stats.get(can_id, {})
        comparison[can_id] = {
            "normal_count": normal.get("count", 0),
            "attack_count": attack.get("count", 0),
            "count_delta": attack.get("count", 0) - normal.get("count", 0),
            "normal_rate_msg_s": normal.get("rate_msg_s", 0.0),
            "attack_rate_msg_s": attack.get("rate_msg_s", 0.0),
            "rate_delta_msg_s": attack.get("rate_msg_s", 0.0) - normal.get("rate_msg_s", 0.0),
            "normal_mean_period_s": normal.get("mean_timestamp_diff", 0.0),
            "attack_mean_period_s": attack.get("mean_timestamp_diff", 0.0),
            "mean_period_delta_s": attack.get("mean_timestamp_diff", 0.0)
            - normal.get("mean_timestamp_diff", 0.0),
        }
    return comparison


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as file:
        json.dump(data, file, indent=4)


def write_csv(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = [{"can_id": f"0x{can_id}", **values} for can_id, values in data.items()]
    if not rows:
        path.write_text("")
        return
    fieldnames = list(rows[0].keys())
    with path.open("w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def maybe_write_plots(output_dir, normal_stats, attack_stats):
    try:
        import matplotlib.pyplot as plt
    except ImportError:
        print("[WARN] matplotlib is not installed; skipping plots.")
        return

    output_dir.mkdir(parents=True, exist_ok=True)
    all_ids = sorted(set(normal_stats) | set(attack_stats))
    labels = [f"0x{can_id}" for can_id in all_ids]
    x_positions = range(len(all_ids))
    width = 0.4

    normal_counts = [normal_stats.get(can_id, {}).get("count", 0) for can_id in all_ids]
    attack_counts = [attack_stats.get(can_id, {}).get("count", 0) for can_id in all_ids]
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar([x - width / 2 for x in x_positions], normal_counts, width, label="normal")
    ax.bar([x + width / 2 for x in x_positions], attack_counts, width, label="spoofing")
    ax.set_ylabel("messages")
    ax.set_xlabel("CAN ID")
    ax.set_title("CAN message count by scenario")
    ax.set_xticks(list(x_positions))
    ax.set_xticklabels(labels, rotation=45, ha="right")
    ax.legend()
    fig.tight_layout()
    fig.savefig(output_dir / "message_counts_by_id.png", dpi=150)
    plt.close(fig)

    normal_periods = [normal_stats.get(can_id, {}).get("mean_timestamp_diff", 0.0) for can_id in all_ids]
    attack_periods = [attack_stats.get(can_id, {}).get("mean_timestamp_diff", 0.0) for can_id in all_ids]
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar([x - width / 2 for x in x_positions], normal_periods, width, label="normal")
    ax.bar([x + width / 2 for x in x_positions], attack_periods, width, label="spoofing")
    ax.set_ylabel("mean inter-arrival period (s)")
    ax.set_xlabel("CAN ID")
    ax.set_title("CAN period distribution by scenario")
    ax.set_xticks(list(x_positions))
    ax.set_xticklabels(labels, rotation=45, ha="right")
    ax.legend()
    fig.tight_layout()
    fig.savefig(output_dir / "mean_period_by_id.png", dpi=150)
    plt.close(fig)


def analyze_single(input_path):
    print("Analyzing CAN bus data")
    df = read_capture(input_path)
    stats = compute_statistics(df)
    print(f"Rows analyzed: {len(df)}")
    print(f"Unique CAN IDs: {[f'0x{can_id}' for can_id in stats]}")
    print(f"CAN IDs Statistics: {json.dumps(stats, indent=4)}")

    output_base = Path(input_path).with_suffix("")
    write_json(output_base.with_name(output_base.name + "_statistics.json"), stats)
    return stats


def analyze_comparison(args):
    output_dir = Path(args.output_dir)
    normal_df = read_capture(args.normal)
    attack_df = read_capture(args.attack)
    normal_stats = compute_statistics(normal_df)
    attack_stats = compute_statistics(attack_df)
    comparison = compare_statistics(normal_stats, attack_stats)

    write_json(output_dir / "normal_statistics.json", normal_stats)
    write_json(output_dir / "spoofing_statistics.json", attack_stats)
    write_json(output_dir / "normal_vs_spoofing_comparison.json", comparison)
    write_csv(output_dir / "normal_statistics.csv", normal_stats)
    write_csv(output_dir / "spoofing_statistics.csv", attack_stats)
    write_csv(output_dir / "normal_vs_spoofing_comparison.csv", comparison)
    if args.plots:
        maybe_write_plots(output_dir, normal_stats, attack_stats)

    print(f"Normal rows analyzed: {len(normal_df)}")
    print(f"Spoofing rows analyzed: {len(attack_df)}")
    print(f"Etapa 3 analysis written to {output_dir}")
    print(json.dumps(comparison, indent=4))


def main():
    parser = argparse.ArgumentParser(description="Analyze CAN bus captures and compare Etapa 3 scenarios.")
    parser.add_argument(
        "--input",
        default="candump-2026-04-17_225932_parsed.csv",
        help="Path to one parsed candump CSV or raw candump .log file.",
    )
    parser.add_argument("--normal", help="Normal-operation capture (.log or parsed .csv).")
    parser.add_argument("--attack", help="Spoofing-attack capture (.log or parsed .csv).")
    parser.add_argument(
        "--output-dir",
        default="data/etapa3_analysis",
        help="Directory for comparison JSON, CSV and graph outputs.",
    )
    parser.add_argument(
        "--plots",
        action="store_true",
        help="Generate PNG bar charts for counts and mean inter-arrival periods.",
    )
    args = parser.parse_args()

    if args.normal or args.attack:
        if not args.normal or not args.attack:
            parser.error("--normal and --attack must be provided together.")
        analyze_comparison(args)
    else:
        analyze_single(args.input)


if __name__ == "__main__":
    main()
