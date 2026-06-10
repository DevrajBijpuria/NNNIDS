import numpy as np
import pandas as pd
from collections import defaultdict
from datetime import datetime

ML_FEATURES = [
    "packet_count",
    "packet_rate",
    "syn_ratio",
    "unique_dst_ports",
    "avg_payload_size",
    "port_scan_score",
]


class FeatureEngineer:

    def extract_features(self, packets: list) -> pd.DataFrame:
        if not packets:
            return pd.DataFrame()

        ip_groups: dict = defaultdict(list)
        for pkt in packets:
            ip_groups[pkt.src_ip].append(pkt)

        return pd.DataFrame([self._compute(src_ip, pkts) for src_ip, pkts in ip_groups.items()])

    def _compute(self, src_ip: str, pkts: list) -> dict:
        packet_count = len(pkts)
        timestamps = [p.timestamp for p in pkts]
        time_span = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 1.0
        packet_rate = packet_count / max(time_span, 1.0)

        syn_count = sum(1 for p in pkts if "S" in p.flags)
        syn_ratio = syn_count / packet_count

        dst_ports = [p.dst_port for p in pkts]
        unique_dst_ports = len(set(dst_ports))
        avg_payload_size = float(np.mean([p.payload_size for p in pkts]))

        port_scan_score = (unique_dst_ports / packet_count) * syn_ratio

        port_series = pd.Series(dst_ports).value_counts()
        port_probs = port_series / port_series.sum()
        connection_diversity = float(-np.sum(port_probs * np.log2(port_probs + 1e-10)))

        return {
            "src_ip": src_ip,
            "packet_count": packet_count,
            "packet_rate": packet_rate,
            "syn_count": syn_count,
            "syn_ratio": syn_ratio,
            "unique_dst_ports": unique_dst_ports,
            "avg_payload_size": avg_payload_size,
            "port_scan_score": port_scan_score,
            "connection_diversity": connection_diversity,
            "timestamp": datetime.now().isoformat(),
        }

    def get_feature_vector(self, features_df: pd.DataFrame, src_ip: str) -> dict | None:
        if features_df is None or features_df.empty:
            return None
        row = features_df[features_df["src_ip"] == src_ip]
        return row.iloc[0].to_dict() if not row.empty else None