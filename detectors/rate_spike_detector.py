from storage import Alert
from utils import SlidingCounter
from normalize import PacketInfo

class RateDetector:
    """
    Rate spike: too many packets within a short time window.
    OSI: L3/L4 (IP, TCP/UDP).
    """
    def __init__(self, threshold_pps: int, window_sec: int = 1):
        self.threshold_pps = int(threshold_pps)
        self.counter = SlidingCounter(window_sec=window_sec)

    def process(self, p: PacketInfo):
        # Counting packets
        c = self.counter.add("ALL", p.ts)
        # If count > threshold -> alert
        if c > self.threshold_pps:
            return Alert(
                ts=float(p.ts),
                alert_type="RATE_SPIKE",
                severity="MEDIUM",
                osi_layer="L3/L4",
                details=f"Suspicious packet rate: {c} pkt/{self.counter.window_sec}s"
            )
        return None