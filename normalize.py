from dataclasses import dataclass
from typing import Optional

@dataclass
class PacketInfo:
    ts: float
    proto: str  # ARP/IP/TCP/UDP/ICMP/OTHER
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_flags: Optional[str] = None  # "S", "A", etc.


def normalize_scapy(pkt) -> PacketInfo:
    """
    Приводимо scapy packet до єдиного формату PacketInfo,
    щоб детектори були незалежні від бібліотеки.
    """
    ts = getattr(pkt, "time", None)
    if ts is None:
        import time
        ts = time.time()

    info = PacketInfo(ts=ts, proto="OTHER")

    # Ethernet (MAC)
    if pkt.haslayer("Ether"):
        eth = pkt.getlayer("Ether")
        info.src_mac = getattr(eth, "src", None)
        info.dst_mac = getattr(eth, "dst", None)

    # ARP
    if pkt.haslayer("ARP"):
        arp = pkt.getlayer("ARP")
        info.proto = "ARP"
        info.src_ip = getattr(arp, "psrc", None)
        info.dst_ip = getattr(arp, "pdst", None)
        # hwsrc/hwdst інколи корисніше за Ether
        info.src_mac = getattr(arp, "hwsrc", info.src_mac)
        info.dst_mac = getattr(arp, "hwdst", info.dst_mac)
        return info

    # IP
    if pkt.haslayer("IP"):
        ip = pkt.getlayer("IP")
        info.proto = "IP"
        info.src_ip = getattr(ip, "src", None)
        info.dst_ip = getattr(ip, "dst", None)

    # TCP
    if pkt.haslayer("TCP"):
        tcp = pkt.getlayer("TCP")
        info.proto = "TCP"
        info.src_port = int(getattr(tcp, "sport", 0) or 0)
        info.dst_port = int(getattr(tcp, "dport", 0) or 0)
        # flags у scapy може бути числом або строкою
        flags = getattr(tcp, "flags", "")
        info.tcp_flags = str(flags)
        return info

    # UDP
    if pkt.haslayer("UDP"):
        udp = pkt.getlayer("UDP")
        info.proto = "UDP"
        info.src_port = int(getattr(udp, "sport", 0) or 0)
        info.dst_port = int(getattr(udp, "dport", 0) or 0)
        return info

    # ICMP
    if pkt.haslayer("ICMP"):
        info.proto = "ICMP"
        return info

    return info