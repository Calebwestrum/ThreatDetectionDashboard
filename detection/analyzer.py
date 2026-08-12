import csv
from collections import Counter

LOG_FILE = "../data/security_logs.csv"

def load_logs():
    with open(LOG_FILE, "r") as file:
        return list(csv.DictReader(file))
    
def detect_brute_force(logs):
    failed_logins = [
        log for log in logs
        if log["event_type"] == "login"
        and log["status"] == "failure"
    ]
    
    ip_counts = Counter(log["source_ip"] for log in failed_logins)
    alerts = []
    
    for ip, count in ip_counts.items():
        if count >= 5:
            alerts.append({
                "type": "Brute Force Attack",
                "source_ip": ip,
                "failed_attempts": count
            })
            
    return alerts

logs = load_logs()
alerts = detect_brute_force(logs)

print("Security Analysis")
print("-----------------")

for alert in alerts:
    print(
        f"[ALERT] {alert['type']} | "
        f"IP: {alert['source_ip']} | "
        f"Failed Attempts: {alert['failed_attempts']}"
    )