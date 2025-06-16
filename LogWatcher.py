# LogWatcher  by Gabriel Pereira
# command : python logwatcher.py --log sample_log-auth.txt --blacklist blacklist.txt

import re
import argparse
from datetime import datetime, timedelta
from collections import defaultdict


def parse_args():
    parser = argparse.ArgumentParser(description="LogWatcher - Simple Log File Analyzer")
    parser.add_argument('--log', required=True, help='Path to log file')
    parser.add_argument('--blacklist', help='Path to blacklist file (IP per line)')
    parser.add_argument('--threshold', type=int, default=5, help='Failed attempts threshold')
    parser.add_argument('--window', type=int, default=10, help='Time window in minutes')
    return parser.parse_args()


def load_blacklist(path):
    if not path:
        return set()
    with open(path) as f:
        return set(line.strip() for line in f if line.strip())


def extract_events(log_path):
    pattern = re.compile(r'(?P<timestamp>\w+ +\d+ +\d+:\d+:\d+).*?Failed password for.*from (?P<ip>\d+\.\d+\.\d+\.\d+)')
    events = []
    with open(log_path) as f:
        for line in f:
            match = pattern.search(line)
            if match:
                try:
                    time_str = match.group("timestamp")
                    time_fmt = "%b %d %H:%M:%S"
                    # Attach current year
                    time_obj = datetime.strptime(time_str, time_fmt).replace(year=datetime.now().year)
                    ip = match.group("ip")
                    events.append((time_obj, ip))
                except Exception as e:
                    continue
    return events


def analyze(events, threshold, window):
    suspects = defaultdict(list)
    alerts = set()
    for time_obj, ip in events:
        suspects[ip].append(time_obj)

    for ip, times in suspects.items():
        times.sort()
        for i in range(len(times)):
            count = 1
            for j in range(i + 1, len(times)):
                if times[j] - times[i] <= timedelta(minutes=window):
                    count += 1
                else:
                    break
            if count >= threshold:
                alerts.add(ip)
                break
    return alerts


def main():
    args = parse_args()
    blacklist = load_blacklist(args.blacklist)
    events = extract_events(args.log)
    alerts = analyze(events, args.threshold, args.window)

    print("\n=== Suspicious IPs Detected ===")
    for ip in sorted(alerts):
        status = "BLACKLISTED" if ip in blacklist else "---"
        print(f"{ip} {status}")

    print("\nTotal Events:", len(events))
    print("IPs Flagged:", len(alerts))


if __name__ == '__main__':
    main()
