# -*- coding: utf-8 -*-
import os
import sys
import zipfile
import urllib.request
import re
import subprocess
import time
import shutil
import ssl
import json
import socket
import atexit
import random
from concurrent.futures import ThreadPoolExecutor

REPO = "Flowseal/zapret-discord-youtube"
TEMP_DIR = "zapret_temp"
LOCAL_ZIP_NAME = "release.zip"
SESSION_FILE = os.path.join(TEMP_DIR, "orchestrator_session.json")
TIMEOUT = 8.0  # Оптимальный таймаут для заблокированных соединений

# Полный, синхронизированный список сетевых целей для проверки
TEST_TARGETS = {
    "YouTube Main": "https://www.youtube.com",
    "YouTube Video CDN": "https://rr1---sn-axq7sn7s.googlevideo.com",
    "Discord Website": "https://discord.com",
    "Discord Gateway": "https://gateway.discord.gg",
    "Discord CDN": "https://discordcdn.com",
    "Discord Updates": "https://updates.discord.com"
}

ORIGINAL_DNS = {}
RESOLVED_IPS = {}
original_getaddrinfo = socket.getaddrinfo

# Структура сложного комплексного конфига
COMPLEX_CONFIG_TEMPLATE = (
    '"{winws}" --wf-tcp=80,443,2053,2083,2087,2096,8443 --wf-udp=443,19294-19344,50000-50100 '
    '--filter-udp=443 --hostlist="{list_general}" --hostlist="{list_general_user}" '
    '--hostlist-exclude="{list_exclude}" --hostlist-exclude="{list_exclude_user}" '
    '--ipset-exclude="{ipset_exclude}" --ipset-exclude="{ipset_exclude_user}" {udp_general} --new '
    '--filter-udp=19294-19344,50000-50100 --filter-l7=discord,stun {udp_discord} --new '
    '--filter-tcp=2053,2083,2087,2096,8443 --hostlist-domains=discord.media {tcp_discord_media} --new '
    '--filter-tcp=443 --hostlist="%LISTS%list-discord.txt" {tcp_discord} --new '
    '--filter-tcp=443 --hostlist="%LISTS%list-google.txt" --ip-id=zero {tcp_google} --new '
    '--filter-tcp=80,443 --hostlist="%LISTS%list-general.txt" --hostlist="%LISTS%list-general-user.txt" '
    '--hostlist-exclude="%LISTS%list-exclude.txt" --hostlist-exclude="%LISTS%list-exclude-user.txt" '
    '--ipset-exclude="%LISTS%ipset-exclude.txt" --ipset-exclude="%LISTS%ipset-exclude-user.txt" {tcp_general} --new '
    '--filter-udp=443 --ipset="{ipset_all}" --hostlist-exclude="%LISTS%list-exclude.txt" '
    '--hostlist-exclude="%LISTS%list-exclude-user.txt" --ipset-exclude="%LISTS%ipset-exclude.txt" '
    '--ipset-exclude="%LISTS%ipset-exclude-user.txt" {udp_ipset} --new '
    '--filter-tcp=80,443,8443 --ipset="%LISTS%ipset-all.txt" --hostlist-exclude="%LISTS%list-exclude.txt" '
    '--hostlist-exclude="%LISTS%list-exclude-user.txt" --ipset-exclude="%LISTS%ipset-exclude.txt" --ipset-exclude="%LISTS%ipset-exclude-user.txt" {tcp_ipset}'
)

COMPLEX_PROFILES = [
    {
        "name": "Профиль 1: Flowseal Classic (ALT11) [Мульти-сплит + фейки]",
        "udp_general": '--dpi-desync=fake --dpi-desync-repeats=11 --dpi-desync-fake-quic="{bin}quic_initial_www_google_com.bin"',
        "udp_discord": '--dpi-desync=fake --dpi-desync-fake-discord="{bin}quic_initial_dbankcloud_ru.bin" --dpi-desync-fake-stun="{bin}quic_initial_dbankcloud_ru.bin" --dpi-desync-repeats=6',
        "tcp_discord_media": '--dpi-desync=fake,multisplit --dpi-desync-split-seqovl=681 --dpi-desync-split-pos=1 --dpi-desync-fooling=ts --dpi-desync-repeats=8 --dpi-desync-split-seqovl-pattern="{bin}tls_clienthello_www_google_com.bin" --dpi-desync-fake-tls="{bin}tls_clienthello_www_google_com.bin"',
        "tcp_google": '--dpi-desync=fake,multisplit --dpi-desync-split-seqovl=681 --dpi-desync-split-pos=1 --dpi-desync-fooling=ts --dpi-desync-repeats=8 --dpi-desync-split-seqovl-pattern="{bin}tls_clienthello_www_google_com.bin" --dpi-desync-fake-tls="{bin}tls_clienthello_www_google_com.bin"',
        "tcp_general": '--dpi-desync=fake,multisplit --dpi-desync-split-seqovl=664 --dpi-desync-split-pos=1 --dpi-desync-fooling=ts --dpi-desync-repeats=8 --dpi-desync-split-seqovl-pattern="{bin}tls_clienthello_max_ru.bin" --dpi-desync-fake-tls="{bin}stun.bin" --dpi-desync-fake-tls="{bin}tls_clienthello_max_ru.bin" --dpi-desync-fake-http="{bin}tls_clienthello_max_ru.bin"',
        "udp_ipset": '--dpi-desync=fake --dpi-desync-repeats=11 --dpi-desync-fake-quic="{bin}quic_initial_www_google_com.bin"',
        "tcp_ipset": '--dpi-desync=fake,multisplit --dpi-desync-split-seqovl=664 --dpi-desync-split-pos=1 --dpi-desync-fooling=ts --dpi-desync-repeats=8 --dpi-desync-split-seqovl-pattern="{bin}tls_clienthello_max_ru.bin" --dpi-desync-fake-tls="{bin}stun.bin" --dpi-desync-fake-tls="{bin}tls_clienthello_max_ru.bin" --dpi-desync-fake-http="{bin}tls_clienthello_max_ru.bin"'
    }
]

def patched_getaddrinfo(*args, **kwargs):
    host = None
    if len(args) > 0:
        host = args[0]
    elif 'host' in kwargs:
        host = kwargs['host']

    if host in RESOLVED_IPS:
        if len(args) > 0:
            new_args = list(args)
            new_args[0] = RESOLVED_IPS[host]
            return original_getaddrinfo(*new_args, **kwargs)
        else:
            kwargs['host'] = RESOLVED_IPS[host]
            return original_getaddrinfo(*args, **kwargs)
            
    return original_getaddrinfo(*args, **kwargs)

socket.getaddrinfo = patched_getaddrinfo

def is_admin():
    try:
        return os.getuid() == 0
    except AttributeError:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0

def get_active_interfaces():
    try:
        cmd = "powershell -Command \"Get-NetIPInterface -ConnectionState Connected -AddressFamily IPv4 | Select-Object -ExpandProperty InterfaceAlias\""
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, encoding='cp866')
        interfaces = [line.strip() for line in res.stdout.split('\n') if line.strip()]
        return list(set(interfaces))
    except Exception:
        return []

def backup_and_set_dns(interfaces):
    print("[*] Временная настройка системного DNS (1.1.1.1 / 8.8.8.8)...")
    for iface in interfaces:
        try:
            cmd_backup = f"powershell -Command \"Get-DnsClientServerAddress -InterfaceAlias '{iface}' -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses\""
            res = subprocess.run(cmd_backup, shell=True, capture_output=True, text=True, encoding='cp866')
            dns_list = [line.strip() for line in res.stdout.split('\n') if line.strip()]
            
            ORIGINAL_DNS[iface] = dns_list
            
            cmd_set = f"powershell -Command \"Set-DnsClientServerAddress -InterfaceAlias '{iface}' -ServerAddresses ('1.1.1.1', '8.8.8.8')\""
            subprocess.run(cmd_set, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"    -> Адаптер '{iface}': DNS изменен на 1.1.1.1")
        except Exception as e:
            print(f"    [!] Не удалось изменить DNS для '{iface}': {e}")

def restore_dns():
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

atexit.register(restore_dns)

def kill_existing_zapret():
    if sys.platform == "win32":
        subprocess.run("taskkill /F /IM winws.exe", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run("taskkill /F /IM goodbyedpi.exe", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def sanitize_winws_args(args_str):
    args_str = args_str.replace("%GameFilterTCP%", "")
    args_str = args_str.replace("%GameFilterUDP%", "")
    args_str = re.sub(r',+', ',', args_str)
    args_str = re.sub(r',(\s|--|$)', r'\1', args_str)
    args_str = re.sub(r'(=),', r'\1', args_str)
    return re.sub(r'\s+', ' ', args_str).strip()

def ensure_lists_exist(lists_dir):
    lists_dir = os.path.abspath(lists_dir).replace("\\", "/")
    os.makedirs(lists_dir, exist_ok=True)
    required_files = [
        "list-general.txt", "list-general-user.txt",
        "list-exclude.txt", "list-exclude-user.txt",
        "ipset-exclude.txt", "ipset-exclude-user.txt",
        "ipset-all.txt", "list-google.txt", "list-discord.txt"
    ]
    for filename in required_files:
        file_path = os.path.join(lists_dir, filename).replace("\\", "/")
        if not os.path.exists(file_path):
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write("")
            except Exception:
                pass

def _async_curl_worker(name):
    from core.diagnostics import test_target_impersonated
    url = TEST_TARGETS[name]
    status = test_target_impersonated(url, timeout=TIMEOUT)
    score = 0
    if status == "OK":
        score = 20
    elif status == "RESET":
        score = 5
    elif status == "TIMEOUT" or status == "ERROR":
        score = 2
    return name, status, score

def test_raw_cmd_scored(cmd_str, bat_dir, targets_to_test):
    kill_existing_zapret()
    time.sleep(0.3)
    
    # Заменяем все системные пути Windows на прямые слэши во избежание сбоев CMD
    if sys.platform == "win32":
        cmd_str = cmd_str.replace("\\", "/")
        bat_dir = os.path.abspath(bat_dir).replace("\\", "/")
    
    process = None
    results = {}
    total_score = 0
    
    try:
        process = subprocess.Popen(
            cmd_str,
            shell=True,
            cwd=bat_dir,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
        )
        
        # Сокращаем задержку старта до 0.8 сек для кратного ускорения тестов
        time.sleep(0.8)
        poll = process.poll()
        if poll is not None:
            stderr_bytes = process.stderr.read()
            stderr_err = stderr_bytes.decode('cp866', errors='ignore')
            print(f"\n    [!] КРИТИЧЕСКАЯ ОШИБКА: winws.exe завершился сразу после старта (код {poll}).")
            if stderr_err.strip():
                print(f"        Подробности ошибки:\n        {stderr_err.strip()}")
            return {}, 0
            
        with ThreadPoolExecutor(max_workers=len(targets_to_test)) as executor:
            futures = [executor.submit(_async_curl_worker, name) for name in targets_to_test]
            # Выводим детальный лог проверок в реальном времени
            for f in futures:
                name, status, score = f.result()
                results[name] = status
                total_score += score
                print(f"        -> {name:18} : {status}")
                
    except Exception as e:
        print(f"    [!] Сбой запуска процесса: {e}")
    finally:
        if process:
            if sys.platform == "win32":
                subprocess.run(f"taskkill /F /T /PID {process.pid}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                process.terminate()
    return results, total_score

def test_raw_cmd(cmd_str, bat_dir, targets_to_test):
    results, _ = test_raw_cmd_scored(cmd_str, bat_dir, targets_to_test)
    passed = [name for name, status in results.items() if status == "OK"]
    return passed