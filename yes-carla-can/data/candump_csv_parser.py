import argparse
import pandas as pd


def main():
    parser = argparse.ArgumentParser(description="Parse a candump log file into a CSV.")
    parser.add_argument(
        "--input",
        default="candump-2026-04-17_225932.log",
        help="Path to the candump .log file to parse (default: candump-2026-04-17_225932.log)",
    )
    args = parser.parse_args()

    print("candump csv parser")

    # Open the candump file
    with open(args.input, 'r') as file:
        lines = file.readlines()

    # Parse the lines into a DataFrame
    data = []
    for line in lines:
        parts = line.strip().split()
        if len(parts) >= 3:
            timestamp = parts[0].replace("(", "").replace(")", "")
            bus = parts[1]
            data_bytes = ' '.join(parts[2:])
            can_id = data_bytes.split("#")[0]
            payload = data_bytes.split("#")[1]
            data.append({'timestamp': timestamp, 'bus': bus, 'can_id': can_id, 'payload': payload})

    # Export to a DataFrame
    df = pd.DataFrame(data)

    # Export to csv
    filename = args.input.rsplit('.', 1)[0] + '_parsed'
    df.to_csv(f'{filename}.csv', index=False)
    print(f"candump csv parser finished. Data exported to {filename}.csv")

if __name__ == "__main__":
    main()
