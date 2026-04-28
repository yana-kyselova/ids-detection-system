from collections import defaultdict
from storage import Alert
from normalize import PacketInfo

class ArpSpoofDetector:
    """
    ARP spoofing: One IP address -> multiple MAC addresses within a single window.
    OSI: L2(Data Link Layer).
    """
    def __init__(self, mac_changes_threshold: int, window_sec: int, whitelist_ips=None, whitelist_macs=None):
        self.window_sec = int(window_sec)
        self.mac_changes_threshold = int(mac_changes_threshold)
        self.whitelist_ips = set(whitelist_ips or [])
        self.whitelist_macs = set(m.lower() for m in (whitelist_macs or []))

        # Map[ip] -> list of (ts, mac)
        self.history = defaultdict(list)

    def process(self, p: PacketInfo):
        if p.proto != "ARP":
            return None

        if not p.src_ip or not p.src_mac:
            return None

        if p.src_ip in self.whitelist_ips:
            return None

        mac = p.src_mac.lower()
        if mac in self.whitelist_macs:
            return None

        # Map new (ts, mac) tuple to src_ip
        self.history[p.src_ip].append((p.ts, mac))

        # Cleaning old records
        border = p.ts - self.window_sec
        self.history[p.src_ip] = [(ts, m) for (ts, m) in self.history[p.src_ip] if ts >= border]

        macs = {m for (_, m) in self.history[p.src_ip]}
        # Multiple MACs for one IP within window = potential ARP spoofing.
        if len(macs) >= 2:
            return Alert(
                ts=float(p.ts),
                alert_type="ARP_SPOOF",
                severity="HIGH",
                osi_layer="L2",
                src=p.src_ip,
                details=f"IP maps to multiple MACs within {self.window_sec}s: {sorted(macs)}"
            )
        return None