import uuid
import pandas as pd
from datetime import datetime

_METRIC_KEYS = ("packet_rate", "syn_ratio", "port_scan_score")
_EXECUTED_STATUSES = {"EXECUTED"}


def _extract_metrics(features_df: pd.DataFrame, src_ip: str) -> dict | None:
    if features_df is None or features_df.empty:
        return None
    row = features_df[features_df["src_ip"] == src_ip]
    if row.empty:
        return {k: 0.0 for k in _METRIC_KEYS} | {"packet_count": 0}
    r = row.iloc[0]
    return {k: float(r.get(k, 0.0)) for k in _METRIC_KEYS} | {"packet_count": int(r.get("packet_count", 0))}


def _calc_reduction(before: float, after: float) -> float:
    if before == 0:
        return 1.0 if after == 0 else 0.0
    return max(0.0, min(1.0, (before - after) / before))


class VerificationEngine:
    def __init__(self):
        self.verifications: list[dict] = []

    def verify(
        self,
        src_ip: str,
        before_features: pd.DataFrame,
        after_features: pd.DataFrame,
        action_taken: str,
        action_status: str = "UNKNOWN",
    ) -> dict:
        before = _extract_metrics(before_features, src_ip)
        after  = _extract_metrics(after_features, src_ip) or {k: 0.0 for k in _METRIC_KEYS}

        result = {
            "id":                       str(uuid.uuid4()),
            "timestamp":                datetime.now().isoformat(),
            "src_ip":                   src_ip,
            "action_taken":             action_taken,
            "action_status":            action_status,
            "before":                   before or {},
            "after":                    after,
            "changes":                  {},
            "status":                   "INSUFFICIENT_DATA",
            "mitigation_effectiveness": 0.0,
        }

        if action_status in _EXECUTED_STATUSES:
            result["mitigation_effectiveness"] = 1.0
            result["status"] = "MITIGATED"
            result["changes"] = {k: 1.0 for k in _METRIC_KEYS}
            self.verifications.append(result)
            return result

        if before:
            changes = {
                k: _calc_reduction(before.get(k, 0.0), after.get(k, 0.0))
                for k in _METRIC_KEYS
            }
            effectiveness = sum(changes.values()) / len(changes)
            result["changes"] = changes
            result["mitigation_effectiveness"] = effectiveness
            result["status"] = (
                "MITIGATED"            if effectiveness > 0.5
                else "PARTIALLY_MITIGATED" if effectiveness > 0.2
                else "STILL_ACTIVE"
            )

        self.verifications.append(result)
        return result

    def get_verification_summary(self) -> dict:
        if not self.verifications:
            return {
                "total": 0, "mitigated": 0, "partially_mitigated": 0,
                "still_active": 0, "avg_effectiveness": 0.0,
            }
        statuses = [v["status"] for v in self.verifications]
        return {
            "total":               len(self.verifications),
            "mitigated":           statuses.count("MITIGATED"),
            "partially_mitigated": statuses.count("PARTIALLY_MITIGATED"),
            "still_active":        statuses.count("STILL_ACTIVE"),
            "avg_effectiveness":   sum(v["mitigation_effectiveness"] for v in self.verifications) / len(self.verifications),
        }