from scapy.all import IP, TCP, send, conf
import time

# --- CONFIGURATION ---
# Use external IP (8.8.8.8) to force traffic through the network interface instead of loopback
target_ip = "8.8.8.8" 
start_port = 1
end_port = 100 
# -----------------

print(f"[*] Initializing port scan on {target_ip}...")
print(f"[*] Active interface: {conf.iface}")

try:
    for port in range(start_port, end_port + 1):
        # Construct a SYN packet for the target destination and port
        packet = IP(dst=target_ip) / TCP(dport=port, flags="S")
        
        # Send the packet without verbose output
        send(packet, verbose=False)
        
        if port % 20 == 0:
            print(f"[>] Scanned {port} ports...")
        
        time.sleep(0.02) # Slightly slow down for stability

    print("\n[+] Attack complete! Check the IDS window.")
except Exception as e:
    print(f"[-] Error: {e}. Please run the terminal as ADMINISTRATOR!")