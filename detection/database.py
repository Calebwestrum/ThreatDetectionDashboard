import sqlite3

DATABASE = "../data/security_alerts.db"


def create_database():
    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            source_ip TEXT,
            target_user TEXT,
            failed_attempts INTEGER,
            timestamp TEXT NOT NULL
        )
    """)

    connection.commit()
    connection.close()


def save_alert(alert):
    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO alerts (
            alert_type,
            severity,
            source_ip,
            target_user,
            failed_attempts,
            timestamp
        )
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        alert["type"],
        alert["severity"],
        alert.get("source_ip"),
        alert.get("target_user"),
        alert.get("failed_attempts"),
        str(alert["timestamp"])
    ))

    connection.commit()
    connection.close()