import csv
from datetime import datetime, timedelta

LOG_FILE = "../data/security_logs.csv"


def load_logs():
    with open(LOG_FILE, "r") as file:
        logs = list(csv.DictReader(file))

    for log in logs:
        log["timestamp"] = datetime.strptime(
            log["timestamp"],
            "%Y-%m-%d %H:%M:%S"
        )

    return logs


def detect_brute_force(logs):
    failed_logins = [
        log for log in logs
        if log["event_type"] == "login"
        and log["status"] == "failure"
    ]

    # Group failed logins by IP address
    ip_logs = {}

    for log in failed_logins:
        ip = log["source_ip"]

        if ip not in ip_logs:
            ip_logs[ip] = []

        ip_logs[ip].append(log)

    alerts = []

    # Look for 5+ failures within a 5-minute window
    for ip, logs in ip_logs.items():
        logs.sort(key=lambda log: log["timestamp"])

        for i in range(len(logs)):
            window_start = logs[i]["timestamp"]
            window_end = window_start + timedelta(minutes=5)

            attempts = [
                log for log in logs[i:]
                if log["timestamp"] <= window_end
            ]

            if len(attempts) >= 5:
                alerts.append({
                    "type": "Brute Force Attack",
                    "source_ip": ip,
                    "target_user": attempts[0]["user"],
                    "failed_attempts": len(attempts),
                    "first_attempt": window_start
                })
                break

    return alerts


logs = load_logs()
alerts = detect_brute_force(logs)

print("Security Analysis")
print("-----------------")

for alert in alerts:
    print(
        f"[ALERT] {alert['type']} | "
        f"IP: {alert['source_ip']} | "
        f"Target: {alert['target_user']} | "
        f"Failed Attempts: {alert['failed_attempts']}"
    )