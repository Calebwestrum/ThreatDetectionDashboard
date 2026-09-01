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

                if len(attempts) >= 10:
                    severity = "CRITICAL"
                elif len(attempts) >= 7:
                    severity = "HIGH"
                else:
                    severity = "MEDIUM"

                alerts.append({
                    "type": "Brute Force Attack",
                    "source_ip": ip,
                    "target_user": attempts[0]["user"],
                    "failed_attempts": len(attempts),
                    "timestamp": window_start,
                    "severity": severity
                })
                break

    return alerts

def detect_success_after_brute_force(logs):
    alerts = []

    for i, log in enumerate(logs):
        if log["event_type"] != "login" or log["status"] != "success":
            continue

        user = log["user"]
        login_time = log["timestamp"]

        recent_failures = [
            previous_log
            for previous_log in logs[:i]
            if previous_log["user"] == user
            and previous_log["event_type"] == "login"
            and previous_log["status"] == "failure"
            and login_time - previous_log["timestamp"] <= timedelta(minutes=5)
        ]

        if len(recent_failures) >= 5:
            alerts.append({
                "type": "Potential Account Compromise",
                "target_user": user,
                "source_ip": log["source_ip"],
                "failed_attempts": len(recent_failures),
                "severity": "HIGH",
                "timestamp": login_time
            })

    return alerts

def detect_suspicious_login(logs):
    alerts = []

    for log in logs:
        if log["event_type"] != "login":
            continue

        if log["status"] != "success":
            continue

        if log["country"] != "US":
            alerts.append({
                "type": "Suspicious Geographic Login",
                "source_ip": log["source_ip"],
                "target_user": log["user"],
                "failed_attempts": 0,
                "severity": "MEDIUM",
                "timestamp": log["timestamp"]
            })

    return alerts

logs = load_logs()

alerts = detect_brute_force(logs)
alerts += detect_success_after_brute_force(logs)
alerts += detect_suspicious_login(logs)

print("Security Analysis")
print("-----------------")

for alert in alerts:
    print(
        f"[{alert['severity']}] {alert['type']} | "
        f"IP: {alert.get('source_ip', 'N/A')} | "
        f"Target: {alert.get('target_user', 'N/A')} | "
        f"Failed Attempts: {alert.get('failed_attempts', 'N/A')}"
    )