import uuid
from datetime import datetime

_ATTACK_TAXONOMY: dict = {
    "port_scan": {
        "name": "Port Scan",
        "description": "Attacker probing multiple ports to discover open services and vulnerabilities.",
        "indicators": ["High unique port count", "High SYN ratio"],
        "impact": "Reconnaissance — may precede a targeted attack",
    },
    "syn_flood": {
        "name": "SYN Flood",
        "description": "TCP SYN flood attempting to exhaust server connection table.",
        "indicators": ["Excessive SYN packets", "No corresponding ACK responses"],
        "impact": "Service denial, resource exhaustion",
    },
    "ddos": {
        "name": "DDoS Attack",
        "description": "High-volume traffic flood designed to overwhelm the target.",
        "indicators": ["Packet rate far above baseline", "Sustained high volume"],
        "impact": "Service unavailability",
    },
    "unusual_traffic": {
        "name": "Unusual Traffic Pattern",
        "description": "Traffic rate deviating significantly from the established baseline.",
        "indicators": ["Elevated packet rate vs baseline"],
        "impact": "Potential data exfiltration or scanning",
    },
    "isolation_forest": {
        "name": "ML-Detected Anomaly",
        "description": "Statistical anomaly detected by the Isolation Forest model.",
        "indicators": ["Deviation from learned normal-traffic distribution"],
        "impact": "Unknown threat pattern — requires investigation",
    },
    "known_c2": {
        "name": "Known C2 / Malicious IP",
        "description": "Traffic originating from a known command-and-control or threat-actor IP.",
        "indicators": ["IP matched against threat intelligence feed"],
        "impact": "Active compromise or malware communication",
    },
    "new_device": {
        "name": "New Device Detected",
        "description": "An IP not seen in previous scan windows is generating traffic.",
        "indicators": ["First-time appearance in traffic baseline"],
        "impact": "Unauthorized device or lateral movement",
    },
    "baseline_spike": {
        "name": "Traffic Spike vs Baseline",
        "description": "Packet rate significantly exceeds the historical per-IP average.",
        "indicators": ["Current rate > 3x rolling average"],
        "impact": "Potential data exfiltration or DDoS amplification",
    },
}

_SEVERITY_SCORES: dict = {
    "CRITICAL": 100,
    "HIGH": 75,
    "MEDIUM": 50,
    "LOW": 25,
}

_UNKNOWN_ATTACK = {
    "name": "Unknown Threat",
    "description": "Unclassified detection — no taxonomy entry found.",
    "indicators": [],
    "impact": "Unknown",
}

_THREAT_LABELS: dict = {
    "port_scan":        "network reconnaissance and service discovery",
    "syn_flood":        "TCP connection table exhaustion (Denial of Service)",
    "ddos":             "volumetric Distributed Denial of Service",
    "unusual_traffic":  "potential data exfiltration or lateral scanning",
    "isolation_forest": "an unknown threat pattern outside normal behaviour",
    "known_c2":         "active malware communication or Command & Control activity",
    "new_device":       "unauthorized device access or lateral movement",
    "baseline_spike":   "traffic surge consistent with DDoS amplification or exfiltration",
}


def _build_reason(detection: dict, severity: str, rule_name: str) -> str:
    src_ip   = detection.get("src_ip", "Unknown IP")
    det_type = detection.get("type", "UNKNOWN")
    threat   = _THREAT_LABELS.get(rule_name, "an unclassified threat")

    if det_type == "ML_ANOMALY":
        score = detection.get("anomaly_score", None)
        if score is not None:
            confidence = min(100, int(round((abs(score) / 0.7) * 100)))
            conf_str = f"{confidence}% ML confidence"
        else:
            conf_str = "high ML confidence"
    elif det_type == "THREAT_INTEL":
        conf_str = "100% confidence (threat intelligence match)"
    elif det_type == "SIGNATURE":
        conf_str = "100% confidence (signature rule match)"
    elif det_type == "BEHAVIORAL":
        conf_str = "behavioural confidence"
    else:
        conf_str = "detected confidence"

    extras = []
    pkt_rate = detection.get("packet_rate")
    if pkt_rate:
        extras.append(f"packet rate {pkt_rate:.0f}/s")
    syn_count = detection.get("syn_count")
    if syn_count:
        extras.append(f"{int(syn_count)} SYN packets")
    ports = detection.get("unique_dst_ports")
    if ports:
        extras.append(f"{int(ports)} unique ports scanned")
    detail = detection.get("detail")
    if detail:
        extras.append(detail)

    extra_str = ", ".join(extras)
    context   = f" ({extra_str})" if extra_str else ""

    return (
        f"IP {src_ip} was flagged with {conf_str} and {severity} severity{context}, "
        f"indicating {threat}."
    )


class DiagnosisEngine:
    def diagnose(self, detection: dict) -> dict:
        rule_name = detection.get("rule_name", "unknown")
        severity  = detection.get("severity", "MEDIUM")
        info      = _ATTACK_TAXONOMY.get(rule_name, _UNKNOWN_ATTACK)

        return {
            "id":             str(uuid.uuid4()),
            "timestamp":      datetime.now().isoformat(),
            "src_ip":         detection.get("src_ip", "unknown"),
            "detection_type": detection.get("type", "UNKNOWN"),
            "attack_type":    rule_name,
            "attack_name":    info["name"],
            "description":    info["description"],
            "reason":         _build_reason(detection, severity, rule_name),
            "severity":       severity,
            "severity_score": _SEVERITY_SCORES.get(severity, 50),
            "indicators":     info["indicators"],
            "impact":         info["impact"],
            "raw_detection":  detection,
            "status":         "DETECTED",
        }

    def diagnose_batch(self, detections: list[dict]) -> list[dict]:
        return [self.diagnose(d) for d in detections]