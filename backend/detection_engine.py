import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from feature_engineering import ML_FEATURES

import socket

def _get_local_ips() -> set[str]:
    """Return all IPs assigned to this machine."""
    ips = {"127.0.0.1"}
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            addr = info[4][0]
            if "." in addr:
                ips.add(addr)
    except Exception:
        pass
    return ips

_LOCAL_IPS = _get_local_ips()

_SIGNATURES: dict = {
    "port_scan": {
        "condition": lambda f: f["unique_dst_ports"] > 15 and f["syn_ratio"] > 0.75 and f["src_ip"] not in _LOCAL_IPS,
        "severity": "HIGH",
    },
    "syn_flood": {
        "condition": lambda f: f["syn_count"] > 300 and f["syn_ratio"] > 0.85 and f["src_ip"] not in _LOCAL_IPS,
        "severity": "CRITICAL",
    },
    "ddos": {
        "condition": lambda f: f["packet_rate"] > 500 and f["packet_count"] > 1000 and f["src_ip"] not in _LOCAL_IPS,
        "severity": "CRITICAL",
    },
    "unusual_traffic": {
        "condition": lambda f: f["packet_rate"] > 200 and f["src_ip"] not in _LOCAL_IPS,
        "severity": "MEDIUM",
    },
}


class DetectionEngine:

    def __init__(self):
        self.model = IsolationForest(contamination=0.1, random_state=42, n_estimators=100)
        self.scaler = StandardScaler()
        self.is_trained = False

    def train(self, features_df: pd.DataFrame) -> bool:
        if features_df.empty or len(features_df) < 2:
            return False
        X = features_df[ML_FEATURES].fillna(0)
        self.scaler.fit_transform(X)
        self.model.fit(self.scaler.transform(X))
        self.is_trained = True
        return True

    def detect(self, features_df: pd.DataFrame, threat_intel=None, behavioral_engine=None) -> list[dict]:
        detections: list[dict] = []

        for _, row in features_df.iterrows():
            src_ip = row["src_ip"]

            if src_ip in _LOCAL_IPS:
                continue
            if threat_intel and threat_intel.is_trusted(src_ip)[0]:
                continue

            detections.extend(self._signature_detect(row))
            if threat_intel:
                detections.extend(self._threat_intel_detect(row, threat_intel))

        detections.extend(self._ml_detect(features_df, threat_intel))

        if behavioral_engine is not None:
            detections.extend(behavioral_engine.detect(features_df, trusted_check=threat_intel))

        return detections

    def _signature_detect(self, row: pd.Series) -> list[dict]:
        results = []
        for rule_name, rule in _SIGNATURES.items():
            try:
                if rule["condition"](row):
                    results.append({
                        "type": "SIGNATURE",
                        "rule_name": rule_name,
                        "severity": rule["severity"],
                        "src_ip": row["src_ip"],
                    })
            except Exception:
                continue
        return results

    def _threat_intel_detect(self, row: pd.Series, threat_intel) -> list[dict]:
        is_malicious, reason = threat_intel.is_malicious(row["src_ip"])
        if not is_malicious:
            return []
        return [{
            "type": "THREAT_INTEL",
            "rule_name": "known_c2",
            "severity": "CRITICAL",
            "src_ip": row["src_ip"],
            "detail": reason,
        }]

    def _ml_detect(self, features_df: pd.DataFrame, threat_intel=None) -> list[dict]:
        if not self.is_trained or features_df.empty:
            return []
        missing = [col for col in ML_FEATURES if col not in features_df.columns]
        if missing:
            return []

        X = features_df[ML_FEATURES].fillna(0)
        scaled = self.scaler.transform(X)
        preds  = self.model.predict(scaled)
        scores = self.model.score_samples(scaled)

        results = []
        for idx, (pred, score) in enumerate(zip(preds, scores)):
            src_ip = features_df.iloc[idx]["src_ip"]
            if src_ip in _LOCAL_IPS:
                continue
            if threat_intel and threat_intel.is_trusted(src_ip)[0]:
                continue
            if pred == -1:
                severity = "CRITICAL" if score < -0.5 else "HIGH" if score < -0.3 else "MEDIUM"
                results.append({
                    "type": "ML_ANOMALY",
                    "rule_name": "isolation_forest",
                    "severity": severity,
                    "src_ip": src_ip,
                    "anomaly_score": float(score),
                })
        return results