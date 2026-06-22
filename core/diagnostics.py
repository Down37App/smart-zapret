# -*- coding: utf-8 -*-
import os
import sys
import socket
import ssl
import time
import subprocess
import json
import re
import urllib.request
from concurrent.futures import ThreadPoolExecutor

TEST_TARGETS = {
    "YouTube Main": "https://www.youtube.com",
    "YouTube Video CDN": "https://rr1---sn-axq7sn7s.googlevideo.com",
    "Discord Website": "https://discord.com",
    "Discord Gateway": "https://gateway.discord.gg"
}

ORIGINAL_DNS = {}
ORIGINAL_RESOLV_CONF = ""

def is_admin():
    try:
        return os.getuid() == 0
    except AttributeError:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0

def get_active_interfaces():
    if sys.platform == "win32":
        try:
            cmd = "powershell -Command \"Get-NetIPInterface -ConnectionState Connected -AddressFamily IPv4 | Select-Object -ExpandProperty InterfaceAlias\""
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True, encoding='cp866')
            interfaces = [line.strip() for line in res.stdout.split('\n') if line.strip()]
            return list(set(interfaces))
        except Exception:
            return []
    else:
        try:
            res = subprocess.run("ip route show default", shell=True, capture_output=True, text=True)
            match = re.search(r'dev (\S+)', res.stdout)
            if match:
                return [match.group(1)]
        except Exception:
            pass
        try:
            return [d for d in os.listdir("/sys/class/net/") if d != "lo"]
        except Exception:
            return []

def set_custom_dns(interfaces, dns_ip):
    global ORIGINAL_RESOLV_CONF
    print(f"[*] Установка системного DNS на {dns_ip}...")
    if sys.platform == "win32":
        for iface in interfaces:
            try:
                if iface not in ORIGINAL_DNS:
                    cmd_backup = f"powershell -Command \"Get-DnsClientServerAddress -InterfaceAlias '{iface}' -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses\""
                    res = subprocess.run(cmd_backup, shell=True, capture_output=True, text=True, encoding='cp866')
                    dns_list = [line.strip() for line in res.stdout.split('\n') if line.strip()]
                    ORIGINAL_DNS[iface] = dns_list
                
                cmd_set = f"powershell -Command \"Set-DnsClientServerAddress -InterfaceAlias '{iface}' -ServerAddresses ('{dns_ip}')\""
                subprocess.run(cmd_set, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                print(f"    -> Адаптер '{iface}': DNS изменился на {dns_ip}")
            except Exception as e:
                print(f"    [!] Не удалось изменить DNS для '{iface}': {e}")
    else:
        try:
            if os.path.exists("/etc/resolv.conf"):
                with open("/etc/resolv.conf", "r") as f:
                    ORIGINAL_RESOLV_CONF = f.read()
            with open("/etc/resolv.conf", "w") as f:
                f.write(f"nameserver {dns_ip}\n")
            print(f"    -> Сетевой resolv.conf изменен на {dns_ip}")
        except Exception as e:
            print(f"    [-] Не удалось изменить DNS в Linux: {e}")

def restore_dns():
    global ORIGINAL_RESOLV_CONF
    if sys.platform == "win32":
        if not ORIGINAL_DNS:
            return
        print("\n[*] Восстановление исходных системных настроек DNS...")
        for iface, dns_list in ORIGINAL_DNS.items():
            try:
                dns_list = [d for d in dns_list if d]
                if dns_list:
                    dns_str = ",".join([f"'{d}'" for d in dns_list])
                    cmd_restore = f"powershell -Command \"Set-DnsClientServerAddress -InterfaceAlias '{iface}' -ServerAddresses ({dns_str})\""
                else:
                    cmd_restore = f"powershell -Command \"Set-DnsClientServerAddress -InterfaceAlias '{iface}' -ResetServerAddresses\""
                subprocess.run(cmd_restore, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                print(f"    -> Адаптер '{iface}': DNS успешно восстановлен.")
            except Exception as e:
                print(f"    [!] Ошибка восстановления для '{iface}': {e}")
    else:
        if ORIGINAL_RESOLV_CONF:
            print("\n[*] Восстановление исходного resolv.conf...")
            try:
                with open("/etc/resolv.conf", "w") as f:
                    f.write(ORIGINAL_RESOLV_CONF)
                print("    -> Сетевой resolv.conf успешно восстановлен.")
            except Exception as e:
                print(f"    [-] Ошибка восстановления DNS: {e}")

def get_real_ip_via_doh(domain):
    doh_url = f"https://cloudflare-dns.com/dns-query?name={domain}&type=A"
    req = urllib.request.Request(doh_url, headers={
        'Accept': 'application/dns-json',
        'User-Agent': 'Mozilla/5.0'
    })
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode('utf-8'))
            if "Answer" in data:
                for answer in data["Answer"]:
                    if answer["type"] == 1:
                        return answer["data"]
    except Exception:
        pass
    return None

def _test_single_ttl(ip, port, ttl):
    """Поток проверки одного сетевого хопа."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.5)
    try:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
    except OSError:
        pass
    
    start_time = time.time()
    err = s.connect_ex((ip, port))
    s.close()
    elapsed = (time.time() - start_time) * 1000
    return ttl, err, elapsed

def detect_tspu_hop(target_host="www.youtube.com", port=443, max_ttl=25):
    """
    Быстрый параллельный TCP TTL Traceroute.
    Опрашивает все хопы СИНХРОННО, завершая весь тест за 1.5 секунды на всё!
    """
    print(f"[*] Сверхбыстрое многопоточное сканирование сетевого пути до {target_host}...")
    try:
        ip = socket.gethostbyname(target_host)
    except socket.gaierror:
        ip = get_real_ip_via_doh(target_host)
        if not ip:
            print("    [!] Не удалось разрешить IP адрес хоста.")
            return None

    futures_list = []
    # Запускаем все TTL-запросы одновременно в пуле потоков
    with ThreadPoolExecutor(max_workers=max_ttl) as executor:
        futures = [executor.submit(_test_single_ttl, ip, port, ttl) for ttl in range(1, max_ttl + 1)]
        for f in futures:
            try:
                futures_list.append(f.result())
            except Exception:
                pass

    # Сортируем результаты по TTL
    futures_list.sort(key=lambda x: x[0])

    tspu_detected_hop = None
    for ttl, err, elapsed in futures_list:
        if err in [10054, 10053, 111, 113, 104]: # Коды ошибок Windows и Linux (RST / Connection refused)
            print(f"    -> Хоп {ttl:02d}: Получен сигнал RST (Сброс связи) за {elapsed:.1f} мс. ТСПУ обнаружен!")
            if not tspu_detected_hop:
                tspu_detected_hop = ttl
        elif err == 0:
            print(f"    -> Хоп {ttl:02d}: Успешное прямое подключение к серверу за {elapsed:.1f} мс.")
            if not tspu_detected_hop:
                tspu_detected_hop = ttl
        elif err == 10061:
            print(f"    -> Хоп {ttl:02d}: Подключение отклонено (порт закрыт, узел достигнут).")
            if not tspu_detected_hop:
                tspu_detected_hop = ttl

    if tspu_detected_hop:
        return tspu_detected_hop

    print("    [-] ТСПУ не обнаружен или трафик полностью поглощается без ответов.")
    return None

def test_target_impersonated(url, timeout=8.0):
    """
    Проверяет доступность узла через нативный SSL-сокет Windows.
    Идеально совместима с WinDivert, так как работает через Winsock ОС.
    """
    try:
        host = url.split("://")[1].split("/")[0]
    except Exception:
        host = url

    # Резолвим IP через DoH
    ip = get_real_ip_via_doh(host)
    if not ip:
        try:
            ip = socket.gethostbyname(host)
        except Exception:
            return "ERR_DNS (Сбой DNS-резолва)"

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        
        # Запускаем нативное рукопожатие TLS с передачей SNI
        conn = context.wrap_socket(s, server_hostname=host)
        conn.connect((ip, 443))
        conn.close()
        return "OK"
    except socket.timeout:
        return "TIMEOUT (Таймаут соединения)"
    except Exception as e:
        err = str(e).lower()
        if "reset" in err or "10054" in err or "10053" in err or "broken pipe" in err or "104" in err:
            return "RESET (Сброс связи ТСПУ)"
        if "handshake" in err or "ssl" in err:
            return "TLS_ERR (Сбой рукопожатия TLS)"
        
        # Увеличили лимит среза до 100 символов, чтобы видеть ошибки полностью
        clean_err = re.sub(r'[^a-zA-Z0-9_ :\-]', '', str(e))[:100].strip()
        return f"ERR: {clean_err}"

def classify_blocking_symptoms(ggc_node=None):
    """
    Классифицирует характер фильтрации в вашей сети.
    """
    symptoms = {
        "DNS_POISONED": False,
        "TCP_RESET": False,
        "TLS_RESET": False
    }
    
    try:
        system_ip = socket.gethostbyname("www.youtube.com")
    except socket.gaierror:
        system_ip = None
    doh_ip = get_real_ip_via_doh("www.youtube.com")
    if system_ip and doh_ip and system_ip != doh_ip:
        symptoms["DNS_POISONED"] = True

    if doh_ip:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3.0)
            s.connect((doh_ip, 443))
            s.close()
        except Exception:
            symptoms["TCP_RESET"] = True

    yt_status = test_target_impersonated("https://www.youtube.com", timeout=8.0)
    # Ростелеком (бесшумный сброс пакетов / TIMEOUT / ERROR) теперь распознается как блокировка!
    if yt_status in ["RESET", "TIMEOUT"] or "ERR" in yt_status or "TLS_ERR" in yt_status:
        symptoms["TLS_RESET"] = True

    return symptoms

# -*- coding: utf-8 -*-
# Дописать в конец файла core/diagnostics.py:

import random

def build_dns_query(domain):
    """Конструирует бинарный пакет DNS-запроса (A-record) на чистом Python."""
    tx_id = random.getrandbits(16).to_bytes(2, byteorder='big')
    flags = b'\x01\x00'      # Стандартный запрос с требованием рекурсии
    qdcount = b'\x00\x01'    # 1 вопрос
    ancount = b'\x00\x00'
    nscount = b'\x00\x00'
    arcount = b'\x00\x00'
    
    # Кодируем домен (например, discord.com -> \x07discord\x03com\x00)
    parts = domain.split('.')
    qname = b""
    for part in parts:
        if not part: continue
        qname += len(part).to_bytes(1, byteorder='big') + part.encode('utf-8')
    qname += b'\x00'
    
    qtype = b'\x00\x01'   # Тип A (IPv4)
    qclass = b'\x00\x01'  # Класс IN
    
    return tx_id + flags + qdcount + ancount + nscount + arcount + qname + qtype + qclass

def parse_dns_response(data):
    """Декодирует бинарный ответ DNS и извлекает IPv4-адреса."""
    try:
        if len(data) < 12:
            return []
        qdcount = int.from_bytes(data[4:6], byteorder='big')
        ancount = int.from_bytes(data[6:8], byteorder='big')
        
        ptr = 12
        # Пропускаем секцию вопросов
        for _ in range(qdcount):
            while data[ptr] != 0:
                if (data[ptr] & 0xC0) == 0xC0:
                    ptr += 2
                    break
                else:
                    ptr += 1 + data[ptr]
            else:
                ptr += 1
            ptr += 4 # Пропускаем QTYPE и QCLASS
            
        ips = []
        # Парсим секцию ответов (Answers)
        for _ in range(ancount):
            if (data[ptr] & 0xC0) == 0xC0:
                ptr += 2
            else:
                while data[ptr] != 0:
                    ptr += 1 + data[ptr]
                ptr += 1
            
            atype = int.from_bytes(data[ptr:ptr+2], byteorder='big')
            ptr += 8 # Пропускаем CLASS, TTL
            rdlength = int.from_bytes(data[ptr:ptr+2], byteorder='big')
            ptr += 2
            
            if atype == 1 and rdlength == 4: # Тип A (IPv4)
                ip = f"{data[ptr]}.{data[ptr+1]}.{data[ptr+2]}.{data[ptr+3]}"
                ips.append(ip)
            ptr += rdlength
        return ips
    except Exception:
        return []

def verify_ip_legitimacy(ip, domain, timeout=2.5):
    """Проверяет, действительно ли IP принадлежит домену (через TLS Handshake)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        sock.connect((ip, 443))
        secure_sock = context.wrap_socket(sock, server_hostname=domain)
        secure_sock.close()
        return True
    except Exception:
        return False
    finally:
        sock.close()

def analyze_dns_spoofing(domain="discord.com", resolver="8.8.8.8"):
    """
    Анализирует DNS-трафик на предмет перехвата и подмены (DNS Spoofing).
    Возвращает статус: 'clean', 'poisoned', 'intercepted' (порт 53 заблокирован).
    """
    # 1. Получаем чистый эталонный IP через DoH
    secure_ip = get_real_ip_via_doh(domain)
    if not secure_ip:
        return "unknown" # Не удалось получить эталон

    # 2. Шлем прямой UDP DNS запрос на порт 53
    query = build_dns_query(domain)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3.0)
    
    try:
        sock.sendto(query, (resolver, 53))
        data, addr = sock.recvfrom(1024)
    except socket.timeout:
        return "intercepted" # Полный блок незашифрованного DNS
    except Exception:
        return "unknown"
    finally:
        sock.close()
        
    unencrypted_ips = parse_dns_response(data)
    if not unencrypted_ips:
        return "poisoned" # Пустой или некорректный ответ

    # 3. Сверяем IP адреса
    # Если пересечение есть — DNS чист
    if secure_ip in unencrypted_ips:
        return "clean"

    # 4. Проверяем легитимность полученного по UDP IP-адреса.
    # Если TLS-рукопожатие на этот IP с целевым SNI падает — DNS отравлен.
    for ip in unencrypted_ips:
        if verify_ip_legitimacy(ip, domain):
            return "clean" # IP прошел проверку, это Geo-IP / Round-Robin

    return "poisoned"