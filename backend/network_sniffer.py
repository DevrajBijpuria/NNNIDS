import time
import threading
from dataclasses import dataclass
from typing import Optional, Callable
import logging

logger = logging.getLogger(__name__)

try:
    from scapy.all import sniff, get_if_list, conf, IP, TCP, UDP as ScapyUDP
    _SCAPY_AVAILABLE = True
except Exception:
    _SCAPY_AVAILABLE = False


@dataclass
class Packet:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    flags: str
    payload_size: int


def _detect_interface() -> Optional[str]:
    if not _SCAPY_AVAILABLE:
        return None

    try:
        from scapy.arch.windows import get_windows_if_list
        candidates = []
        for iface in get_windows_if_list():
            guid = iface.get("guid", "")
            ips = iface.get("ips", [])
            real_ips = [
                ip for ip in ips
                if "." in ip
                and not ip.startswith("127.")
                and not ip.startswith("169.254.")
            ]
            if real_ips and guid:
                candidates.append((iface.get("name", ""), guid, real_ips[0]))

        if candidates:
            name, guid, ip = candidates[0]
            logger.info("Auto-selected interface: %s (%s) — IP %s", name, guid, ip)
            return rf"\Device\NPF_{guid}"
    except Exception:
        pass

    ifaces = get_if_list()
    if ifaces:
        return ifaces[0]

    default = str(conf.iface)
    return default if default else None


def _parse_scapy_packet(pkt) -> Optional[Packet]:
    if IP not in pkt:
        return None
    is_tcp = TCP in pkt
    is_udp = ScapyUDP in pkt
    proto    = "TCP" if is_tcp else "UDP" if is_udp else "OTHER"
    flags    = str(pkt[TCP].flags) if is_tcp else ""
    src_port = pkt[TCP].sport if is_tcp else (pkt[ScapyUDP].sport if is_udp else 0)
    dst_port = pkt[TCP].dport if is_tcp else (pkt[ScapyUDP].dport if is_udp else 0)
    return Packet(
        timestamp=time.time(),
        src_ip=pkt[IP].src,
        dst_ip=pkt[IP].dst,
        src_port=src_port,
        dst_port=dst_port,
        protocol=proto,
        flags=flags,
        payload_size=len(pkt),
    )


class NetworkSniffer:
    def __init__(self, mode: str = "live", interface: Optional[str] = None):
        self.mode = mode
        self.interface = interface or (_detect_interface() if mode == "live" else None)
        self._streaming = False
        self._stream_thread: Optional[threading.Thread] = None
        self._stream_buffer: list[Packet] = []
        self._buffer_lock = threading.Lock()

    def start_capture(self, duration: int = 10) -> list[Packet]:
        if self.mode == "live":
            return self._capture_live(duration)
        return self._capture_synthetic(duration)

    def _capture_live(self, duration: int) -> list[Packet]:
        if not _SCAPY_AVAILABLE:
            raise RuntimeError(
                "Scapy is installed but no packet capture provider was found. "
                "Install Npcap from https://npcap.com and restart the backend "
                "(run as Administrator for full access)."
            )

        captured: list[Packet] = []

        def _handler(pkt):
            p = _parse_scapy_packet(pkt)
            if p:
                captured.append(p)

        logger.info("Live capture started on interface=%s for %ds", self.interface, duration)
        try:
            sniff(
                prn=_handler,
                timeout=duration,
                store=0,
                iface=self.interface,
            )
        except PermissionError:
            raise RuntimeError(
                "Packet capture requires Administrator privileges. "
                "Restart the backend with 'Run as Administrator'."
            )

        logger.info("Live capture complete — %d packets", len(captured))
        return captured

    def start_streaming(self, window_seconds: int = 10, on_window: Optional[Callable] = None):
        if self._streaming:
            return
        self._streaming = True
        self._stream_thread = threading.Thread(
            target=self._stream_loop,
            args=(window_seconds, on_window),
            daemon=True,
        )
        self._stream_thread.start()

    def stop_streaming(self):
        self._streaming = False

    def _stream_loop(self, window_seconds: int, on_window: Optional[Callable]):
        while self._streaming:
            try:
                packets = self.start_capture(duration=window_seconds)
                with self._buffer_lock:
                    self._stream_buffer = packets
                if on_window and packets:
                    on_window(packets)
            except Exception as e:
                logger.error("Stream window error: %s", e)
                time.sleep(2)

    def get_stream_buffer(self) -> list[Packet]:
        with self._buffer_lock:
            return list(self._stream_buffer)

    def _capture_synthetic(self, duration: int) -> list[Packet]:
        import random

        _NORMAL_IPS = ["192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.13"]
        _ATTACK_IPS = ["10.0.0.50", "10.0.0.51"]
        _PORTS = [80, 443, 22, 8080, 53, 3306]

        packets: list[Packet] = []
        start = time.time()

        while time.time() - start < duration:
            now = time.time()
            for _ in range(random.randint(5, 10)):
                packets.append(Packet(
                    timestamp=now,
                    src_ip=random.choice(_NORMAL_IPS),
                    dst_ip="192.168.1.100",
                    src_port=random.randint(1024, 65535),
                    dst_port=random.choice(_PORTS),
                    protocol="TCP", flags="ACK",
                    payload_size=random.randint(64, 1500),
                ))
            if random.random() < 0.3:
                attacker = random.choice(_ATTACK_IPS)
                for _ in range(random.randint(20, 50)):
                    packets.append(Packet(
                        timestamp=now, src_ip=attacker, dst_ip="192.168.1.100",
                        src_port=random.randint(1024, 65535),
                        dst_port=random.randint(1, 1024),
                        protocol="TCP", flags="SYN", payload_size=0,
                    ))
            if random.random() < 0.2:
                attacker = random.choice(_ATTACK_IPS)
                for _ in range(random.randint(100, 200)):
                    packets.append(Packet(
                        timestamp=now, src_ip=attacker, dst_ip="192.168.1.100",
                        src_port=random.randint(1024, 65535),
                        dst_port=80, protocol="TCP", flags="SYN",
                        payload_size=random.randint(0, 100),
                    ))
            time.sleep(0.1)

        return packets