from collections import defaultdict
from datetime import datetime

import pandas as pd

_SPIKE_MULTIPLIER = 3.0
_MIN_HISTORY_SCANS = 2


class BehavioralEngine:

    def __init__(self):
        self._baselines: dict[str, list[float]] = defaultdict(list)
        self._seen_ips: set[str] = set()
        self._scan_hour_history: dict[str, list[int]] = defaultdict(list)

    def detect(self, features_df: pd.DataFrame, trusted_check=None) -> list[dict]:
        if features_df is None or features_df.empty:
            return []

        detections: list[dict] = []
        current_hour = datetime.now().hour

        for _, row in features_df.iterrows():
            ip = row["src_ip"]
            rate = float(row.get("packet_rate", 0.0))
            pkt_count = int(row.get("packet_count", 0))

            if trusted_check and trusted_check.is_trusted(ip)[0]:
                self._update_baseline(ip, rate, current_hour)
                continue

            detections.extend(self._check_new_device(ip, pkt_count))
            detections.extend(self._check_baseline_spike(ip, rate))
            detections.extend(self._check_odd_hours(ip, current_hour))

            self._update_baseline(ip, rate, current_hour)

        return detections

    def _check_new_device(self, ip: str, packet_count: int = 0) -> list[dict]:
        # Only flag as new device if it sends enough packets to be meaningful.
        # Single-packet noise (DNS, ARP stray, etc.) should not trigger an alert.
        if ip not in self._seen_ips and packet_count >= 5:
            return [{
                "type": "BEHAVIORAL",
                "rule_name": "new_device",
                "severity": "MEDIUM",
                "src_ip": ip,
            }]
        return []

    def _check_baseline_spike(self, ip: str, rate: float) -> list[dict]:
        history = self._baselines.get(ip, [])
        if len(history) < _MIN_HISTORY_SCANS or rate == 0:
            return []
        avg = sum(history) / len(history)
        if avg > 0 and rate > avg * _SPIKE_MULTIPLIER:
            severity = "CRITICAL" if rate > avg * 6 else "HIGH" if rate > avg * 4 else "MEDIUM"
            return [{
                "type": "BEHAVIORAL",
                "rule_name": "baseline_spike",
                "severity": severity,
                "src_ip": ip,
                "detail": f"Rate {rate:.1f} vs avg {avg:.1f} pkt/s",
            }]
        return []

    def _check_odd_hours(self, ip: str, hour: int) -> list[dict]:
        hours_seen = self._scan_hour_history.get(ip, [])
        if len(hours_seen) < _MIN_HISTORY_SCANS:
            return []
        usual_hours = set(hours_seen)
        if hour not in usual_hours and not self._is_business_hour(hour):
            return [{
                "type": "BEHAVIORAL",
                "rule_name": "unusual_traffic",
                "severity": "LOW",
                "src_ip": ip,
                "detail": f"Traffic at hour {hour:02d}:00 — outside observed pattern",
            }]
        return []

    @staticmethod
    def _is_business_hour(hour: int) -> bool:
        return 8 <= hour <= 20

    def _update_baseline(self, ip: str, rate: float, hour: int):
        self._seen_ips.add(ip)
        history = self._baselines[ip]
        history.append(rate)
        if len(history) > 20:
            history.pop(0)
        hour_history = self._scan_hour_history[ip]
        hour_history.append(hour)
        if len(hour_history) > 100:
            hour_history.pop(0)
