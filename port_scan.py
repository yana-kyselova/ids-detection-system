from scapy.all import IP, TCP, send, conf
import time

# --- НААЛАШТУВАННЯ---
# Використовуємо 8.8.8.8, щоб пакети гарантировано пішли в мережу, а не в Loopback
target_ip = "8.8.8.8" 
start_port = 1
end_port = 100 
# -----------------

print(f"[*] Иніціація атаки Port Scanning на {target_ip}...")
print(f"[*] Використаний інтерфейс: {conf.iface}")

try:
    for port in range(start_port, end_port + 1):
        # Створюємо пакет
        packet = IP(dst=target_ip) / TCP(dport=port, flags="S")
        
        # Відправляємо
        send(packet, verbose=False)
        
        if port % 20 == 0:
            print(f"[>] Проскановано {port} портов...")
        
        time.sleep(0.02) # Трішки сповільнюємо для стабільності

    print("\n[+] Атака завершена! Перевір вікно IDS.")
except Exception as e:
    print(f"[-] Помилка: {e}. Запустіть термінал від імені АДМІНІСТРАТОРА!")