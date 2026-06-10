_DECISION_TABLE: dict = {
    ("port_scan", "HIGH"): "BLOCK_IP",
    ("port_scan", "MEDIUM"): "THROTTLE",
    ("port_scan", "LOW"): "MONITOR",
    ("syn_flood", "CRITICAL"): "BLOCK_IP",
    ("syn_flood", "HIGH"): "BLOCK_IP",
    ("syn_flood", "MEDIUM"): "THROTTLE",
    ("ddos", "CRITICAL"): "BLOCK_IP",
    ("ddos", "HIGH"): "BLOCK_IP",
    ("ddos", "MEDIUM"): "QUARANTINE",
    ("unusual_traffic", "HIGH"): "QUARANTINE",
    ("unusual_traffic", "MEDIUM"): "MONITOR",
    ("unusual_traffic", "LOW"): "MONITOR",
    ("isolation_forest", "CRITICAL"): "QUARANTINE",
    ("isolation_forest", "HIGH"): "THROTTLE",
    ("isolation_forest", "MEDIUM"): "MONITOR",
    ("known_c2", "CRITICAL"): "BLOCK_IP",
    ("known_c2", "HIGH"): "BLOCK_IP",
    ("new_device", "MEDIUM"): "MONITOR",
    ("new_device", "HIGH"): "QUARANTINE",
    ("baseline_spike", "CRITICAL"): "QUARANTINE",
    ("baseline_spike", "HIGH"): "THROTTLE",
    ("baseline_spike", "MEDIUM"): "MONITOR",
}

_DEFAULT_ACTION = "MONITOR"

_REASONS: dict = {
    "BLOCK_IP": "Immediate blocking — severity warrants full traffic drop",
    "THROTTLE": "Rate limiting applied to reduce threat impact",
    "QUARANTINE": "Isolating source for safe investigation",
    "MONITOR": "Logging and watching for further escalation",
}


class DecisionEngine:
    """Maps (attack_type, severity) → response action using a deterministic rule table."""

    def decide(self, diagnosis: dict) -> dict:
        attack_type = diagnosis.get("attack_type", "unknown")
        severity = diagnosis.get("severity", "MEDIUM")
        action = _DECISION_TABLE.get((attack_type, severity), _DEFAULT_ACTION)

        return {
            "diagnosis_id": diagnosis.get("id"),
            "src_ip": diagnosis.get("src_ip"),
            "attack_type": attack_type,
            "severity": severity,
            "recommended_action": action,
            "reason": _REASONS.get(action, "Automated decision"),
            "auto_execute": severity in ("CRITICAL", "HIGH"),
            "metadata": {
                "attack_name": diagnosis.get("attack_name"),
                "severity_score": diagnosis.get("severity_score"),
            },
        }

    def decide_batch(self, diagnoses: list[dict]) -> list[dict]:
        return [self.decide(d) for d in diagnoses]

    def get_decision_table(self) -> dict:
        return dict(_DECISION_TABLE) 