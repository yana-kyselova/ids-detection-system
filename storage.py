import json
import os
from dataclasses import dataclass, asdict
from typing import Optional

@dataclass
class Alert:
    ts: float
    alert_type: str
    severity: str
    osi_layer: str
    src: Optional[str] = None
    dst: Optional[str] = None
    details: Optional[str] = None


class Storage:
    def __init__(self, alerts_log: str, events_jsonl: str):
        self.alerts_log = alerts_log
        self.events_jsonl = events_jsonl

        # створимо файли, якщо їх немає
        for path in [self.alerts_log, self.events_jsonl]:
            folder = os.path.dirname(path)
            if folder and not os.path.exists(folder):
                os.makedirs(folder, exist_ok=True)

    def write_alert(self, alert: Alert) -> None:
        line = f"[{alert.severity}] {alert.alert_type} ({alert.osi_layer})"
        if alert.src:
            line += f" src={alert.src}"
        if alert.dst:
            line += f" dst={alert.dst}"
        if alert.details:
            line += f" | {alert.details}"

        with open(self.alerts_log, "a", encoding="utf-8") as f:
            f.write(line + "\n")

        with open(self.events_jsonl, "a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(alert), ensure_ascii=False, default=str) + "\n")