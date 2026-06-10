import numpy as np
import pandas as pd
from datetime import datetime

_SEVERITY_WEIGHTS: dict = {
    "CRITICAL": 40,
    "HIGH": 30,
    "MEDIUM": 15,
    "LOW": 5,
}


class RiskEngine:
    """Computes a dynamic 0–100 system risk score from alerts, verifications, and traffic."""

    def __init__(self, baseline_risk: float = 10.0):
        self.current_risk: float = 0.0
        self.baseline_risk = baseline_risk
        self._history: list[dict] = []

    def seed_from_db(self, records: list[dict]):
        self._history = records

    def calculate_risk(
        self,
        alerts: list[dict],
        verifications: list[dict],
        features_df: pd.DataFrame | None = None,
    ) -> dict:
        alert_risk = min(25.0, len(alerts) * 5) if alerts else 0.0

        severity_risk = 0.0
        if alerts:
            severity_risk = max(
                _SEVERITY_WEIGHTS.get(a.get("severity", "LOW"), 5) for a in alerts
            )

        mitigation_risk = 15.0
        if verifications:
            avg_eff = float(np.mean([v.get("mitigation_effectiveness", 0.0) for v in verifications]))
            mitigation_risk = 20.0 * (1.0 - avg_eff)

        traffic_risk = 0.0
        if features_df is not None and not features_df.empty and "packet_rate" in features_df:
            max_rate = float(features_df["packet_rate"].max())
            traffic_risk = 15.0 if max_rate > 100 else 10.0 if max_rate > 50 else 5.0 if max_rate > 20 else 0.0

        components = {
            "alert_risk": alert_risk,
            "severity_risk": severity_risk,
            "mitigation_risk": mitigation_risk,
            "traffic_risk": traffic_risk,
        }

        total = sum(components.values())
        if self.current_risk > 0:
            total = 0.7 * total + 0.3 * self.current_risk
        total = max(0.0, min(100.0, total))
        if not alerts:
            total = max(total, self.baseline_risk)

        self.current_risk = total
        entry = {"timestamp": datetime.now().isoformat(), "risk_score": total}
        self._history.append(entry)

        return {
            "risk_score": round(total, 2),
            "risk_level": self.get_risk_level(),
            "components": components,
            "trend": self.get_trend(),
        }

    def get_risk_level(self, score: float | None = None) -> str:
        s = score if score is not None else self.current_risk
        if s >= 75:
            return "CRITICAL"
        if s >= 50:
            return "HIGH"
        if s >= 25:
            return "MEDIUM"
        return "LOW"

    def get_trend(self) -> str:
        recent = [r["risk_score"] for r in self._history[-5:]]
        if len(recent) < 2:
            return "STABLE"
        slope = recent[-1] - recent[0]
        if slope > 10:
            return "INCREASING"
        if slope < -10:
            return "DECREASING"
        return "STABLE"

    def get_risk_history(self, limit: int = 50) -> list[dict]:
        return self._history[-limit:]

    def reset(self):
        self.current_risk = self.baseline_risk