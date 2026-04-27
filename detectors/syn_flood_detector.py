from collections import defaultdict
from storage import Alert
from normalize import PacketInfo

class SynFloodDetector:
    """
    SYN flood: багато SYN у вікні часу.
    OSI: L4
    """
    def __init__(self, syn_threshold: int, window_sec: int, group_by: str = "dst", whitelist_ips=None):
        self.syn_threshold = int(syn_threshold)
        self.window_sec = int(window_sec)
        self.group_by = group_by  # "dst" або "src"
        self.whitelist_ips = set(whitelist_ips or [])

        # map[key] -> list of ts
        self.history = defaultdict(list)

    def process(self, p: PacketInfo):
        if p.proto != "TCP" or not p.tcp_flags:
            return None

        flags = p.tcp_flags
        is_syn = ("S" in flags) and ("A" not in flags)
        if not is_syn:
            return None

        key = p.dst_ip if self.group_by == "dst" else p.src_ip
        if not key:
            return None

        if key in self.whitelist_ips:
            return None

        self.history[key].append(p.ts)

        border = p.ts - self.window_sec
        self.history[key] = [ts for ts in self.history[key] if ts >= border]

        if len(self.history[key]) >= self.syn_threshold:
            return Alert(
                ts=p.ts,
                alert_type="SYN_FLOOD",
                severity="HIGH",
                osi_layer="L4",
                src=p.src_ip,
                dst=p.dst_ip,
                details=f"SYN count in {self.window_sec}s for {self.group_by}={key}: {len(self.history[key])}"
            )
        return None