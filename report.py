import json
from collections import Counter, defaultdict

def generate_report(events_jsonl: str, report_txt: str) -> None:
    counts = Counter()
    by_severity = Counter()
    by_layer = Counter()
    top_src = Counter()

    with open(events_jsonl, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            e = json.loads(line)
            counts[e.get("alert_type", "UNKNOWN")] += 1
            by_severity[e.get("severity", "UNKNOWN")] += 1
            by_layer[e.get("osi_layer", "UNKNOWN")] += 1
            src = e.get("src")
            if src:
                top_src[src] += 1

    with open(report_txt, "w", encoding="utf-8") as out:
        out.write("=== MINI-IDS REPORT ===\n\n")
        out.write("Alerts by type:\n")
        for k, v in counts.most_common():
            out.write(f"  {k}: {v}\n")

        out.write("\nAlerts by severity:\n")
        for k, v in by_severity.most_common():
            out.write(f"  {k}: {v}\n")

        out.write("\nAlerts by OSI layer:\n")
        for k, v in by_layer.most_common():
            out.write(f"  {k}: {v}\n")

        out.write("\nTop sources:\n")
        for k, v in top_src.most_common(10):
            out.write(f"  {k}: {v}\n")