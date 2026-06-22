#!/bin/bash
# Проверка прав root
if [ "$EUID" -ne 0 ]; then
  echo "[!] Ошибка: Пожалуйста, запустите скрипт через sudo!"
  exit 1
fi

BIN_DIR="$(dirname "$(readlink -f "$0")")/nfq"
LISTS_DIR="$(dirname "$(readlink -f "$0")")/lists"

manage_rules() {
  action="$1"
  # IPv4 Правила
  iptables $action OUTPUT -p tcp -m multiport --dports 80,443 -j NFQUEUE --queue-num 10 --queue-bypass
  iptables $action OUTPUT -p udp -m multiport --dports 443,19294:19344,50000:50100 -j NFQUEUE --queue-num 10 --queue-bypass
  
  # IPv6 Правила (Для предотвращения утечек IPv6 мимо обхода nfqws)
  ip6tables $action OUTPUT -p tcp -m multiport --dports 80,443 -j NFQUEUE --queue-num 10 --queue-bypass
  ip6tables $action OUTPUT -p udp -m multiport --dports 443,19294:19344,50000:50100 -j NFQUEUE --queue-num 10 --queue-bypass
}

cleanup() {
  echo ""
  echo "[*] Восстановление исходных правил фавервола и чистка DNS..."
  manage_rules "-D"
  
  if [ -f /etc/resolv.conf.backup ]; then
    mv /etc/resolv.conf.backup /etc/resolv.conf
  fi
  
  sudo killall -9 nfqws > /dev/null 2>&1
  echo "[+] Сетевые процессы успешно завершены."
  exit 0
}

trap cleanup INT TERM

echo "[*] Настройка DNS-резолвера на 1.1.1.1..."
if [ -f /etc/resolv.conf ]; then
  cp /etc/resolv.conf /etc/resolv.conf.backup
fi
echo "nameserver 1.1.1.1" > /etc/resolv.conf

echo "[*] Настройка правил перенаправления Netfilter..."
manage_rules "-I"

echo "[*] Запуск кроссплатформенного nfqws..."
sudo "/opt/zapret/nfq/nfqws" --qnum=10 --filter-udp=19294-19344,50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-repeats=6 --new --filter-udp=443 --hostlist="$LISTS_DIR/list-youtube.txt" --dpi-desync=fake --dpi-desync-repeats=11 --dpi-desync-fake-quic="/opt/zapret/files/fake/quic_initial_www_google_com.bin" --new --filter-tcp=443 --hostlist="$LISTS_DIR/list-discord.txt" --dpi-desync=disorder --dpi-desync-split-pos=sniext --dpi-desync-fooling=badseq --new --filter-tcp=443 --hostlist="$LISTS_DIR/list-youtube.txt" --dpi-desync=disorder --dpi-desync-split-pos=sniext --dpi-desync-fooling=badseq --new --filter-tcp=80,443 --hostlist="$LISTS_DIR/list-general.txt" --dpi-desync=disorder --dpi-desync-split-pos=sniext --dpi-desync-fooling=badseq &

echo "[+] Мультипрофильный обход запущен."
echo "[!] Для ОСТАНОВКИ обхода нажмите Ctrl+C..."
wait
