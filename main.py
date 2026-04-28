import argparse
import yaml
import time

from capture import capture_live, capture_pcap
from normalize import normalize_scapy
from storage import Storage
from detectors import RateDetector, ArpSpoofDetector, PortScanDetector, SynFloodDetector
from report import generate_report

def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def build_detectors(cfg: dict):
    wl_ips = cfg.get("whitelist", {}).get("ips", [])
    wl_macs = cfg.get("whitelist", {}).get("macs", [])

    th = cfg.get("thresholds", {})

    rate = RateDetector(
        threshold_pps=th.get("rate_threshold_pps", 500),
        window_sec=1
    )

    arp = ArpSpoofDetector(
        mac_changes_threshold=th.get("arp_mac_changes_per_window", 2),
        window_sec=th.get("arp_window_sec", 60),
        whitelist_ips=wl_ips,
        whitelist_macs=wl_macs
    )

    portscan = PortScanDetector(
        ports_threshold=th.get("portscan_ports_per_window", 25),
        window_sec=th.get("portscan_window_sec", 30),
        whitelist_ips=wl_ips
    )

    synflood = SynFloodDetector(
        syn_threshold=th.get("syn_flood_syn_per_window", 120),
        window_sec=th.get("syn_window_sec", 10),
        group_by="dst",
        whitelist_ips=[]
    )

    return [rate, arp, portscan, synflood]

def main():
    parser = argparse.ArgumentParser(description="Mini-IDS (traffic-based, OSI-oriented)")
    parser.add_argument("--config", default="config.yaml", help="Path to config.yaml")
    parser.add_argument("--live", action="store_true", help="Capture live traffic")
    parser.add_argument("--pcap", type=str, default=None, help="Analyze pcap file")
    parser.add_argument("--iface", type=str, default=None, help="Network interface for live capture")
    parser.add_argument("--report", action="store_true", help="Generate report from events.jsonl and exit")
    args = parser.parse_args()
   
    cfg = load_config(args.config)

    out_cfg = cfg.get("output", {})
    storage = Storage(
        alerts_log=out_cfg.get("alerts_log", "alerts.log"),
        events_jsonl=out_cfg.get("events_jsonl", "events.jsonl")
    )

    if args.report:
        generate_report(out_cfg.get("events_jsonl", "events.jsonl"), out_cfg.get("report_txt", "report.txt"))
        print("Report generated.")
        return

    detectors = build_detectors(cfg)

    def on_packet(pkt):
        info = normalize_scapy(pkt)

        # Whitelist check: if src or dst IP is in whitelist, skip processing.
        wl_ips = set(cfg.get("whitelist", {}).get("ips", []))
        if info.src_ip in wl_ips or info.dst_ip in wl_ips:
            return

        for d in detectors:
            alert = d.process(info)
            if alert:
                storage.write_alert(alert)
                print(f"[{alert.severity}] {alert.alert_type} ({alert.osi_layer}) {alert.details or ''}")

    # Offline mode: process traffic from a PCAP file
    if args.pcap:
        capture_pcap(args.pcap, on_packet)
        print("PCAP processed.")
        return

    if args.live or cfg.get("mode") == "live":
        from scapy.all import conf # Import Scapy only when needed (lazy load)
        
        # Interface priority: CLI arg > config file > Scapy auto-detection
        iface = args.iface or cfg.get("iface")
        
        if not iface or iface == "eth0":
            iface = conf.iface
            
        # Ensure interface name is string (handle Scapy bytes return)
        iface_name = str(iface)

        print(f"--- [ IDS ACTIVE ] СЛУХАЮ ТРАФІК: {iface} ---")
        capture_live(iface_name, on_packet)
        return

    # Fallback to config mode if no CLI args provided
    if cfg.get("mode") == "pcap":
        pcap_path = cfg.get("pcap_path")
        if not pcap_path:
            raise SystemExit("No pcap_path in config.yaml")
        capture_pcap(pcap_path, on_packet)
        print("PCAP processed.")
        return

if __name__ == "__main__":
    main()