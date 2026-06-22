# -*- coding: utf-8 -*-
import os
import sys
from core.blockcheck.strategies import find_fake_file

YOUTUBE_DOMAINS = [
    "youtube.com", "www.youtube.com", "youtu.be", "googlevideo.com", 
    "ytimg.com", "ggpht.com", "android.clients.google.com", 
    "play.google.com", "nhacmp3cdn.com"
]

DISCORD_DOMAINS = [
    "discord.com", "gateway.discord.gg", "discordapp.com", "discordapp.net", 
    "discord.gg", "discord.media", "discordcdn.com", "discordapi.com", 
    "dis.gd", "discord.co", "updates.discord.com", "status.discord.com", 
    "discordstatus.com", "media.discordapp.net", "images-ext-1.discordapp.net", 
    "dl2.discordapp.net", "stable.dl2.discordapp.net"
]

GENERAL_DOMAINS = [
    "rutracker.org", "rutracker.net", "wikipedia.org", "censortracker.org", 
    "torproject.org", "medium.com", "protonmail.com"
]

class MultiServiceGenerator:
    def __init__(self, lists_dir):
        self.lists_dir = os.path.abspath(lists_dir).replace("\\", "/")
        os.makedirs(self.lists_dir, exist_ok=True)
        self.is_win = (sys.platform == "win32")

    def _write_hostlist(self, filename, domains):
        """Записывает домены в соответствующий hostlist-файл."""
        filepath = os.path.join(self.lists_dir, filename).replace("\\", "/")
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write("\n".join(domains) + "\n")
            return filepath
        except Exception as e:
            print(f"[-] Не удалось записать hostlist {filename}: {e}")
            return None

    def generate_files(self, best_yt, best_discord, best_general, bin_dir, output_dir):
        """
        Генерирует раздельные списки доменов и собирает оптимальный
        мультипрофильный скрипт запуска с использованием абсолютных системных путей.
        """
        output_dir = os.path.abspath(output_dir).replace("\\", "/")
        bin_dir = os.path.abspath(bin_dir).replace("\\", "/") + "/"
        
        # 1. Записываем списки доменов
        yt_path = self._write_hostlist("list-youtube.txt", YOUTUBE_DOMAINS)
        ds_path = self._write_hostlist("list-discord.txt", DISCORD_DOMAINS)
        gen_path = self._write_hostlist("list-general.txt", GENERAL_DOMAINS)

        if not (yt_path and ds_path and gen_path):
            return False

        # 2. Определение пути к демону nfqws
        resolved_nfqws = os.path.join(bin_dir, "nfqws").replace("\\", "/")
        
        # Находим абсолютный путь к файлу фейка QUIC
        quic_fake_path = find_fake_file("quic_initial_www_google_com.bin", bin_dir)
        
        # Строим QUIC UDP профиль для YouTube в зависимости от наличия .bin файла фейка
        if quic_fake_path:
            quic_profile = f'--filter-udp=443 --hostlist="$LISTS_DIR/list-youtube.txt" --dpi-desync=fake --dpi-desync-repeats=11 --dpi-desync-fake-quic="{quic_fake_path}" --new '
            win_quic_profile = f'--filter-udp=443 --hostlist="%LISTS%list-youtube.txt" --dpi-desync=fake --dpi-desync-repeats=11 --dpi-desync-fake-quic="{quic_fake_path}" --new '
        else:
            # Нативный фолбэк-обход UDP без файла фейка
            quic_profile = f'--filter-udp=443 --hostlist="$LISTS_DIR/list-youtube.txt" --dpi-desync=fake --dpi-desync-repeats=11 --new '
            win_quic_profile = f'--filter-udp=443 --hostlist="%LISTS%list-youtube.txt" --dpi-desync=fake --dpi-desync-repeats=11 --new '

        # 3. Сборка мультипрофильной команды
        if self.is_win:
            cmd = (
                f'--wf-tcp=80,443 --wf-udp=443,19294-19344,50000-50100 '
                # Профиль 1: Discord (Голосовые UDP каналы)
                f'--filter-udp=19294-19344,50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-repeats=6 --new '
                # Профиль 2: YouTube QUIC
                f'{win_quic_profile}'
                # Профиль 3: Discord TCP
                f'--filter-tcp=443 --hostlist="%LISTS%list-discord.txt" {best_discord.to_cmd(bin_dir="%BIN%", raw_desync_only=True)} --new '
                # Профиль 4: YouTube TCP
                f'--filter-tcp=443 --hostlist="%LISTS%list-youtube.txt" --ip-id=zero {best_yt.to_cmd(bin_dir="%BIN%", raw_desync_only=True)} --new '
                # Профиль 5: Общие заблокированные ресурсы (HTTP/HTTPS)
                f'--filter-tcp=80,443 --hostlist="%LISTS%list-general.txt" {best_general.to_cmd(bin_dir="%BIN%", raw_desync_only=True)}'
            )
            
            # Сохранение .bat скрипта для Windows
            bat_path = os.path.join(output_dir, "custom_generated.bat").replace("\\", "/")
            try:
                with open(bat_path, "w", encoding="utf-8") as f:
                    f.write(self._build_windows_bat(cmd))
                print(f"[+] Мультипрофильный BAT-сценарий успешно сгенерирован: {bat_path}")
                return True
            except Exception as e:
                print(f"[-] Ошибка записи BAT-файла: {e}")
                return False
        else:
            # Специфичные настройки nfqws под Linux
            cmd = (
                f'--qnum=10 '
                # Профиль 1: Discord (Голосовые UDP каналы)
                f'--filter-udp=19294-19344,50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-repeats=6 --new '
                # Профиль 2: YouTube QUIC
                f'{quic_profile}'
                # Профиль 3: Discord TCP
                f'--filter-tcp=443 --hostlist="$LISTS_DIR/list-discord.txt" {best_discord.to_cmd(bin_dir="$BIN_DIR/", raw_desync_only=True)} --new '
                # Профиль 4: YouTube TCP
                f'--filter-tcp=443 --hostlist="$LISTS_DIR/list-youtube.txt" {best_yt.to_cmd(bin_dir="$BIN_DIR/", raw_desync_only=True)} --new '
                # Профиль 5: Общие заблокированные ресурсы (HTTP/HTTPS)
                f'--filter-tcp=80,443 --hostlist="$LISTS_DIR/list-general.txt" {best_general.to_cmd(bin_dir="$BIN_DIR/", raw_desync_only=True)}'
            )
            
            # Сохранение .sh скрипта для Linux
            sh_path = os.path.join(output_dir, "custom_generated.sh").replace("\\", "/")
            try:
                with open(sh_path, "w", encoding="utf-8") as f:
                    # Передаем реальный абсолютный путь к nfqws в шаблон генератора
                    f.write(self._build_linux_sh(cmd, resolved_nfqws))
                # Выставляем права на исполнение сценарию
                os.chmod(sh_path, 0o755)
                print(f"[+] Мультипрофильный Bash-сценарий успешно сгенерирован: {sh_path}")
                return True
            except Exception as e:
                print(f"[-] Ошибка записи Bash-файла: {e}")
                return False

    def _build_windows_bat(self, inner_cmd):
        return f"""@echo off
chcp 65001 > nul
cd /d "%~dp0"

:: Проверка прав Администратора
net session >nul 2>&1 || (echo [!] Ошибка: Запустите BAT-файл от имени Администратора! & pause & exit /b)

set "BIN=%~dp0bin\\"
set "LISTS=%~dp0lists\\"
cd /d %BIN%

echo [*] Подготовка сети: временная установка DNS 1.1.1.1 на активных адаптерах...
powershell -Command "Get-NetIPInterface -ConnectionState Connected -AddressFamily IPv4 | Where-Object {{ $_.InterfaceAlias -notlike '*Loopback*' }} | ForEach-Object {{ Set-DnsClientServerAddress -InterfaceAlias $_.InterfaceAlias -ServerAddresses ('1.1.1.1', '8.8.8.8') }}"
ipconfig /flushdns > nul

echo [*] Запуск сбалансированного мультипрофильного обхода DPI...
start "zapret: custom" /min "%BIN%winws.exe" {inner_cmd}

echo [+] Мультипрофильный обход успешно развернут в фоновом режиме.
echo [!] Для ОСТАНОВКИ обхода и автоматического восстановления DNS нажмите любую клавишу...
pause

echo [*] Восстановление исходных системных настроек DNS...
powershell -Command "Get-NetIPInterface -ConnectionState Connected -AddressFamily IPv4 | Where-Object {{ $_.InterfaceAlias -notlike '*Loopback*' }} | Set-DnsClientServerAddress -ResetServerAddresses"
ipconfig /flushdns > nul

echo [*] Завершение процессов winws...
taskkill /F /IM winws.exe > nul 2>&1
echo [+] Сетевые настройки и процессы успешно восстановлены.
"""

# -*- coding: utf-8 -*-
# Внутри core/profiles.py обновляем метод _build_linux_sh:

    def _build_linux_sh(self, inner_cmd, resolved_nfqws):
        return f"""#!/bin/bash
# Проверка прав root
if [ "$EUID" -ne 0 ]; then
  echo "[!] Ошибка: Пожалуйста, запустите скрипт через sudo!"
  exit 1
fi

BIN_DIR="$(dirname "$(readlink -f "$0")")/nfq"
LISTS_DIR="$(dirname "$(readlink -f "$0")")/lists"

manage_rules() {{
  action="$1"
  # IPv4 Правила
  iptables $action OUTPUT -p tcp -m multiport --dports 80,443 -j NFQUEUE --queue-num 10 --queue-bypass
  iptables $action OUTPUT -p udp -m multiport --dports 443,19294:19344,50000:50100 -j NFQUEUE --queue-num 10 --queue-bypass
  
  # IPv6 Правила (Для предотвращения утечек IPv6 мимо обхода nfqws)
  ip6tables $action OUTPUT -p tcp -m multiport --dports 80,443 -j NFQUEUE --queue-num 10 --queue-bypass
  ip6tables $action OUTPUT -p udp -m multiport --dports 443,19294:19344,50000:50100 -j NFQUEUE --queue-num 10 --queue-bypass
}}

cleanup() {{
  echo ""
  echo "[*] Восстановление исходных правил фавервола и чистка DNS..."
  manage_rules "-D"
  
  if [ -f /etc/resolv.conf.backup ]; then
    mv /etc/resolv.conf.backup /etc/resolv.conf
  fi
  
  sudo killall -9 nfqws > /dev/null 2>&1
  echo "[+] Сетевые процессы успешно завершены."
  exit 0
}}

trap cleanup INT TERM

echo "[*] Настройка DNS-резолвера на 1.1.1.1..."
if [ -f /etc/resolv.conf ]; then
  cp /etc/resolv.conf /etc/resolv.conf.backup
fi
echo "nameserver 1.1.1.1" > /etc/resolv.conf

echo "[*] Настройка правил перенаправления Netfilter..."
manage_rules "-I"

echo "[*] Запуск кроссплатформенного nfqws..."
sudo "{resolved_nfqws}" {inner_cmd} &

echo "[+] Мультипрофильный обход запущен."
echo "[!] Для ОСТАНОВКИ обхода нажмите Ctrl+C..."
wait
"""

def best_errors_to_strategy(strategy, bin_dir):
    """Вспомогательная функция для корректного форматирования Discord TCP-команды."""
    return strategy.to_cmd(bin_dir, raw_desync_only=True)