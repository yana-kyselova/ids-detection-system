from scapy.all import sniff, rdpcap

def capture_live(iface: str, callback):
    sniff(iface=iface, prn=callback, store=False)

def capture_pcap(pcap_path: str, callback):
    sniff(offline=pcap_path, prn=callback, store=False)