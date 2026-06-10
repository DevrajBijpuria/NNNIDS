import json
import sqlite3
from datetime import datetime
from typing import Any

_CREATE_ALERTS = """
    CREATE TABLE IF NOT EXISTS alerts (
        id TEXT PRIMARY KEY,
        timestamp TEXT,
        src_ip TEXT,
        attack_type TEXT,
        attack_name TEXT,
        severity TEXT,
        severity_score INTEGER,
        status TEXT,
        data TEXT
    )
"""

_CREATE_ACTIONS = """
    CREATE TABLE IF NOT EXISTS actions (
        id TEXT PRIMARY KEY,
        timestamp TEXT,
        src_ip TEXT,
        action_type TEXT,
        status TEXT,
        execution_log TEXT
    )
"""

_CREATE_VERIFICATIONS = """
    CREATE TABLE IF NOT EXISTS verifications (
        id TEXT PRIMARY KEY,
        timestamp TEXT,
        src_ip TEXT,
        status TEXT,
        mitigation_effectiveness REAL,
        data TEXT
    )
"""

_CREATE_RISK_HISTORY = """
    CREATE TABLE IF NOT EXISTS risk_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        risk_score REAL,
        risk_level TEXT,
        components TEXT
    )
"""

_CREATE_TRAFFIC_LOGS = """
    CREATE TABLE IF NOT EXISTS traffic_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        src_ip TEXT,
        packet_count INTEGER,
        packet_rate REAL,
        features TEXT
    )
"""


class Database:
    def __init__(self, db_type: str = "sqlite", db_path: str = "nnnids.db"):
        path = ":memory:" if db_type == "memory" else db_path
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._create_tables()

    def _create_tables(self):
        cursor = self.conn.cursor()
        for ddl in (
            _CREATE_ALERTS,
            _CREATE_ACTIONS,
            _CREATE_VERIFICATIONS,
            _CREATE_RISK_HISTORY,
            _CREATE_TRAFFIC_LOGS,
        ):
            cursor.execute(ddl)
        self.conn.commit()

    def _exec(self, sql: str, params: tuple = ()):
        cursor = self.conn.cursor()
        cursor.execute(sql, params)
        self.conn.commit()

    def insert_alert(self, alert: dict):
        self._exec(
            """INSERT OR IGNORE INTO alerts
               (id, timestamp, src_ip, attack_type, attack_name, severity, severity_score, status, data)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                alert["id"], alert["timestamp"], alert["src_ip"],
                alert["attack_type"], alert["attack_name"], alert["severity"],
                alert["severity_score"], alert["status"], json.dumps(alert),
            ),
        )

    def insert_action(self, action: dict):
        self._exec(
            """INSERT OR IGNORE INTO actions
               (id, timestamp, src_ip, action_type, status, execution_log)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                action["id"], action["timestamp"], action["src_ip"],
                action["action_type"], action["status"],
                json.dumps(action["execution_log"]),
            ),
        )

    def insert_verification(self, verification: dict):
        self._exec(
            """INSERT OR IGNORE INTO verifications
               (id, timestamp, src_ip, status, mitigation_effectiveness, data)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                verification["id"], verification["timestamp"], verification["src_ip"],
                verification["status"], verification["mitigation_effectiveness"],
                json.dumps(verification),
            ),
        )

    def insert_risk_record(self, risk_data: dict):
        self._exec(
            """INSERT INTO risk_history (timestamp, risk_score, risk_level, components)
               VALUES (?, ?, ?, ?)""",
            (
                risk_data["timestamp"], risk_data["risk_score"],
                risk_data["risk_level"], json.dumps(risk_data["components"]),
            ),
        )

    def get_alerts(self, limit: int = 100) -> list[dict]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT data FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,))
        return [json.loads(row[0]) for row in cursor.fetchall()]

    def get_actions(self, limit: int = 100) -> list[dict]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM actions ORDER BY timestamp DESC LIMIT ?", (limit,))
        return [dict(row) for row in cursor.fetchall()]

    def get_verifications(self, limit: int = 100) -> list[dict]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT data FROM verifications ORDER BY timestamp DESC LIMIT ?", (limit,))
        return [json.loads(row[0]) for row in cursor.fetchall()]

    def get_risk_history(self, limit: int = 100) -> list[dict]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM risk_history ORDER BY timestamp DESC LIMIT ?", (limit,))
        return [dict(row) for row in cursor.fetchall()]

    def get_risk_history_for_engine(self, limit: int = 50) -> list[dict]:
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT timestamp, risk_score FROM risk_history ORDER BY timestamp ASC LIMIT ?", (limit,)
        )
        return [{"timestamp": row["timestamp"], "risk_score": row["risk_score"]} for row in cursor.fetchall()]

    def get_stats(self) -> dict:
        cursor = self.conn.cursor()
        stats: dict[str, Any] = {}
        for key, sql in (
            ("total_alerts", "SELECT COUNT(*) FROM alerts"),
            ("critical_alerts", "SELECT COUNT(*) FROM alerts WHERE severity = 'CRITICAL'"),
            ("total_actions", "SELECT COUNT(*) FROM actions"),
            ("executed_actions", "SELECT COUNT(*) FROM actions WHERE status = 'EXECUTED'"),
            ("mitigated_threats", "SELECT COUNT(*) FROM verifications WHERE status = 'MITIGATED'"),
        ):
            cursor.execute(sql)
            stats[key] = cursor.fetchone()[0]
        return stats

    def close(self):
        self.conn.close()