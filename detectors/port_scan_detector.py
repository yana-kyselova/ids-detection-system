from collections import defaultdict
from storage import Alert
from normalize import PacketInfo

class PortScanDetector:
    """
    SYN port scan: One source IP -> multiple destination ports within a single window.
    OSI: L4(Transport Layer).
    """
    def __init__(self, ports_threshold: int, window_sec: int, whitelist_ips=None):
        self.ports_threshold = int(ports_threshold)
        self.window_sec = int(window_sec)
        self.whitelist_ips = set(whitelist_ips or [])

        # Map[src_ip] -> list of (ts, dst_port)
        self.history = defaultdict(list)

    def process(self, p: PacketInfo):
        if p.proto != "TCP":
            return None
        if not p.src_ip or not p.dst_port or not p.tcp_flags:
            return None

        if p.src_ip in self.whitelist_ips:
            return None

        # SYN scan: SYN flag is set, ACK flag is not set.
        flags = p.tcp_flags
        is_syn = ("S" in flags) and ("A" not in flags)

        if not is_syn:
            return None

        self.history[p.src_ip].append((p.ts, int(p.dst_port)))

        border = p.ts - self.window_sec
        self.history[p.src_ip] = [(ts, port) for (ts, port) in self.history[p.src_ip] if ts >= border]

        ports = {port for (_, port) in self.history[p.src_ip]}
        if len(ports) >= self.ports_threshold:
            return Alert(
                ts=float(p.ts),
                alert_type="PORT_SCAN",
                severity="HIGH",
                osi_layer="L4",
                src=p.src_ip,
                dst=p.dst_ip,
                details=f"Unique dst ports in {self.window_sec}s: {len(ports)}; ports={sorted(list(ports))[:50]}"
            )
        return None