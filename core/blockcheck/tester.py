# -*- coding: utf-8 -*-
import socket
import ssl
import time
import os
import sys
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from core.diagnostics import get_real_ip_via_doh

# Структурированная база целей с указанием транспорта
DEFAULT_TARGETS = {
    "YouTube TCP Main": {"url": "https://www.youtube.com", "transport": "tcp"},
    "YouTube TCP CDN": {"url": "https://rr1---sn-axq7sn7s.googlevideo.com", "transport": "tcp"},
    "Discord TCP Website": {"url": "https://discord.com", "transport": "tcp"},
    "Discord TCP Gateway": {"url": "https://gateway.discord.gg", "transport": "tcp"},
    "GitHub TCP": {"url": "https://github.com", "transport": "tcp"},
    
    # HTTP цель для тестирования порта 80
    "Rutracker HTTP": {"url": "http://rutracker.org", "transport": "tcp_http"},
    
    "YouTube QUIC Main": {"url": "https://www.youtube.com", "transport": "udp"},
    "Google QUIC CDN": {"url": "https://rr1---sn-axq7sn7s.googlevideo.com", "transport": "udp"}
}

class NetworkTester:
    def __init__(self, targets=None, iterations=3, bin_dir=""):
        self.targets = targets or DEFAULT_TARGETS
        self.iterations = iterations
        self.bin_dir = bin_dir

    def _classify_socket_error(self, exc):
        err_str = str(exc).lower()
        if isinstance(exc, ConnectionResetError) or "10054" in err_str or "reset" in err_str:
            return "reset"
        if isinstance(exc, socket.timeout) or "timeout" in err_str:
            return "timeout"
        if isinstance(exc, ssl.SSLEOFError) or "eof" in err_str:
            return "eof"
        if isinstance(exc, ssl.SSLError) or "ssl" in err_str:
            return "tls_error"
        return "http_error"

    def probe_quic_granular(self, ip, port=443, timeout=3.0):
        """
        Низкоуровневый замер UDP/QUIC. Отправляет пакет QUIC Initial
        и ожидает любого ответа от сервера (Server Initial / Version Negotiation).
        """
        bin_path = os.path.join(self.bin_dir, "quic_initial_www_google_com.bin")
        payload = b""
        if os.path.exists(bin_path):
            try:
                with open(bin_path, "rb") as f:
                    payload = f.read()
            except Exception:
                pass
                
        if not payload:
            payload = (
                b'\xc0\x00\x00\x00\x01'  # Long Header, Version 1
                b'\x08\x00\x00\x00\x00\x00\x00\x00\x00'  # Dest Connection ID (8 bytes)
                b'\x00'  # Source Connection ID (0 bytes)
                b'\x00'  # Token Length (0)
                b'\x40\x02'  # Length (2 bytes encoded)
                + b'\x00' * 1200  # Паддинг до минимального размера QUIC пакета
            )

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        start_time = time.time()
        
        try:
            sock.sendto(payload, (ip, port))
            data, addr = sock.recvfrom(2048)
            elapsed = (time.time() - start_time) * 1000.0
            return "OK", elapsed
        except socket.timeout:
            elapsed = (time.time() - start_time) * 1000.0
            return "timeout", elapsed
        except (ConnectionResetError, ConnectionRefusedError):
            elapsed = (time.time() - start_time) * 1000.0
            return "reset", elapsed
        except Exception as e:
            elapsed = (time.time() - start_time) * 1000.0
            return self._classify_socket_error(e), elapsed
        finally:
            sock.close()

    def probe_target_granular_detailed(self, url, timeout=4.0):
        """
        Реверс-инжиниринг сетевого пути: пошаговое выполнение рукопожатия
        с детальной фиксацией фазы сброса, IP адреса и входящего TTL пакетов RST.
        """
        parsed = urllib.parse.urlparse(url)
        host = parsed.netloc
        port = 443 if parsed.scheme == "https" else 80
        
        dns_resolved_ip = "unknown"
        handshake_phase_reached = "resolve"
        received_rst_from_dpi = False
        response_ttl = None
        
        # Шаг 1: DNS-резолв
        try:
            dns_resolved_ip = socket.gethostbyname(host)
        except socket.gaierror:
            ip = get_real_ip_via_doh(host)
            if ip:
                dns_resolved_ip = ip
            else:
                return {
                    "status": "dns_error", "elapsed": 0.0,
                    "handshake_phase_reached": "resolve",
                    "dns_resolved_ip": "unknown", "received_rst_from_dpi": False,
                    "response_ttl": None
                }

        # Шаг 2: TCP соединение (SYN / SYN-ACK)
        handshake_phase_reached = "tcp_connect"
        start_time = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        # На Linux пытаемся перехватить входящий TTL
        if sys.platform != "win32":
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_RECVTTL, 1)
            except Exception:
                pass

        try:
            sock.connect((dns_resolved_ip, port))
        except Exception as e:
            sock.close()
            elapsed = (time.time() - start_time) * 1000.0
            err_type = self._classify_socket_error(e)
            if err_type == "reset":
                received_rst_from_dpi = True
            return {
                "status": err_type, "elapsed": elapsed,
                "handshake_phase_reached": "tcp_connect",
                "dns_resolved_ip": dns_resolved_ip,
                "received_rst_from_dpi": received_rst_from_dpi,
                "response_ttl": None
            }

        # Шаг 3: Передача данных / TLS ClientHello
        if port == 443:
            handshake_phase_reached = "tls_handshake"
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            try:
                secure_sock = context.wrap_socket(sock, server_hostname=host)
                
                # На Linux парсим опцию IP_RECVTTL из сокета через recvmsg
                if sys.platform != "win32":
                    try:
                        secure_sock.setblocking(False)
                        data, ancdata, flags, address = secure_sock.recvmsg(1024, socket.CMSG_LEN(4))
                        for cmsg_level, cmsg_type, cmsg_data in ancdata:
                            if cmsg_level == socket.IPPROTO_IP and cmsg_type == socket.IP_TTL:
                                import struct
                                response_ttl = struct.unpack("i", cmsg_data)[0]
                    except Exception:
                        pass
                        
                secure_sock.close()
            except Exception as e:
                sock.close()
                elapsed = (time.time() - start_time) * 1000.0
                err_type = self._classify_socket_error(e)
                if err_type == "reset":
                    received_rst_from_dpi = True
                return {
                    "status": err_type, "elapsed": elapsed,
                    "handshake_phase_reached": "tls_handshake",
                    "dns_resolved_ip": dns_resolved_ip,
                    "received_rst_from_dpi": received_rst_from_dpi,
                    "response_ttl": response_ttl
                }
        else:
            # Для нешифрованного HTTP/80
            handshake_phase_reached = "http_data"
            try:
                payload = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode('utf-8')
                sock.sendall(payload)
                response = sock.recv(1024)
                sock.close()
            except Exception as e:
                sock.close()
                elapsed = (time.time() - start_time) * 1000.0
                err_type = self._classify_socket_error(e)
                if err_type == "reset":
                    received_rst_from_dpi = True
                return {
                    "status": err_type, "elapsed": elapsed,
                    "handshake_phase_reached": "http_data",
                    "dns_resolved_ip": dns_resolved_ip,
                    "received_rst_from_dpi": received_rst_from_dpi,
                    "response_ttl": None
                }

        elapsed = (time.time() - start_time) * 1000.0
        return {
            "status": "OK", "elapsed": elapsed,
            "handshake_phase_reached": "http_data" if port == 80 else "tls_handshake",
            "dns_resolved_ip": dns_resolved_ip, "received_rst_from_dpi": False,
            "response_ttl": response_ttl
        }

    def _probe_single_target(self, name, target_info):
        """Выполняет цикл проверок с учетом транспорта цели."""
        successes = 0
        latencies = []
        errors_summary = {}
        
        dns_resolved_ip = "unknown"
        handshake_phase_reached = "resolve"
        received_rst_from_dpi = False
        response_ttl = None
        
        parsed = urllib.parse.urlparse(target_info["url"])
        host = parsed.netloc
        
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror:
            ip = get_real_ip_via_doh(host)
            if not ip:
                return {
                    "name": name, "success_rate": 0.0, "avg_latency": 0.0, "latencies": [],
                    "errors": {"dns_error": self.iterations},
                    "dns_resolved_ip": "unknown", "handshake_phase_reached": "resolve",
                    "received_rst_from_dpi": False, "response_ttl": None
                }

        for _ in range(self.iterations):
            if target_info["transport"] == "udp":
                status, elapsed = self.probe_quic_granular(ip)
                dns_resolved_ip = ip
                handshake_phase_reached = "udp_handshake"
            else:
                res = self.probe_target_granular_detailed(target_info["url"])
                status, elapsed = res["status"], res["elapsed"]
                dns_resolved_ip = res["dns_resolved_ip"]
                handshake_phase_reached = res["handshake_phase_reached"]
                received_rst_from_dpi = res["received_rst_from_dpi"]
                response_ttl = res["response_ttl"]
                
            if status == "OK":
                successes += 1
                latencies.append(elapsed)
            else:
                errors_summary[status] = errors_summary.get(status, 0) + 1
            time.sleep(0.1)

        avg_latency = sum(latencies) / len(latencies) if latencies else 0.0
        success_rate = (successes / self.iterations) * 100.0

        return {
            "name": name,
            "success_rate": success_rate,
            "avg_latency": avg_latency,
            "latencies": latencies,
            "errors": errors_summary,
            "dns_resolved_ip": dns_resolved_ip,
            "handshake_phase_reached": handshake_phase_reached,
            "received_rst_from_dpi": received_rst_from_dpi,
            "response_ttl": response_ttl
        }

    def run_parallel_tests(self, active_targets=None):
        """Многопоточный параллельный опрос всех целей."""
        test_set = active_targets if active_targets else self.targets
        results = {}
        with ThreadPoolExecutor(max_workers=len(test_set)) as executor:
            futures = {
                executor.submit(self._probe_single_target, name, info): name 
                for name, info in test_set.items()
            }
            for f in futures:
                name = futures[f]
                try:
                    results[name] = f.result()
                except Exception:
                    results[name] = {
                        "name": name, "success_rate": 0.0, "avg_latency": 0.0, "latencies": [],
                        "errors": {"unknown_error": self.iterations},
                        "dns_resolved_ip": "unknown", "handshake_phase_reached": "resolve",
                        "received_rst_from_dpi": False, "response_ttl": None
                    }
        return results
