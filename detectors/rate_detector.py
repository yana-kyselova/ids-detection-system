from storage import Alert
from utils import SlidingCounter
from normalize import PacketInfo

class RateDetector:
    """
    Детектор аномальної інтенсивності пакетів (pps).
    OSI: L3/L4 (бо мова про загальний потік IP/TCP/UDP/ICMP).
    """
    def __init__(self, threshold_pps: int, window_sec: int = 1):
        self.threshold_pps = int(threshold_pps)
        self.counter = SlidingCounter(window_sec=window_sec)

    def process(self, p: PacketInfo):
        # ключ "ALL" рахує всі пакети
        c = self.counter.add("ALL", p.ts)
        # коли перевищили поріг — сигнал
        if c > self.threshold_pps:
            return Alert(
                ts=p.ts,
                alert_type="RATE_SPIKE",
                severity="MEDIUM",
                osi_layer="L3/L4",
                details=f"Suspicious packet rate: {c} pkt/{self.counter.window_sec}s"
            )
        return None