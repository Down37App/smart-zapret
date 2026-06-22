# -*- coding: utf-8 -*-
import socket
import ssl
import time
import os
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
    
    # Новая HTTP цель для тестирования порта 80
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
        Низкоуровневый тест UDP/QUIC. Отправляет пакет QUIC Initial
        и ожидает любого ответа от сервера (Server Initial / Version Negotiation).
        """
        bin_path = os.path.join(self.bin_dir, "quic_initial_www_google_com.bin")
        payload = b""
        
        # Пытаемся считать готовый слепок Initial пакета
        if os.path.exists(bin_path):
            try:
                with open(bin_path, "rb") as f:
                    payload = f.read()
            except Exception:
                pass
                
        # Если файла нет, используем минимальный валидный QUIC Initial заголовок v1 (RFC 9000)
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
            # Ожидаем ответный UDP пакет от сервера
            data, addr = sock.recvfrom(2048)
            elapsed = (time.time() - start_time) * 1000.0
            return "OK", elapsed
        except socket.timeout:
            elapsed = (time.time() - start_time) * 1000.0
            return "timeout", elapsed
        except (ConnectionResetError, ConnectionRefusedError):
            # В UDP это означает получение ICMP-сообщения Port Unreachable (признак блокировки)
            elapsed = (time.time() - start_time) * 1000.0
            return "reset", elapsed
        except Exception as e:
            elapsed = (time.time() - start_time) * 1000.0
            return self._classify_socket_error(e), elapsed
        finally:
            sock.close()

    def probe_target_granular(self, url, timeout=4.0):
        """Стандартный TCP/TLS сокет-тест."""
        parsed = urllib.parse.urlparse(url)
        host = parsed.netloc
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror:
            ip = get_real_ip_via_doh(host)
            if not ip:
                return "dns_error", 0.0

        start_time = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((ip, 443))
        except Exception as e:
            sock.close()
            elapsed = (time.time() - start_time) * 1000.0
            return self._classify_socket_error(e), elapsed

        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            secure_sock = context.wrap_socket(sock, server_hostname=host)
            secure_sock.close()
        except Exception as e:
            sock.close()
            elapsed = (time.time() - start_time) * 1000.0
            return self._classify_socket_error(e), elapsed

        elapsed = (time.time() - start_time) * 1000.0
        return "OK", elapsed

    def _probe_single_target(self, name, target_info):
        """Выполняет цикл проверок с учетом транспорта цели."""
        successes = 0
        latencies = []
        errors_summary = {}
        
        parsed = urllib.parse.urlparse(target_info["url"])
        host = parsed.netloc
        
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror:
            ip = get_real_ip_via_doh(host)
            if not ip:
                return {
                    "name": name, "success_rate": 0.0, "avg_latency": 0.0, "latencies": [],
                    "errors": {"dns_error": self.iterations}
                }

        for _ in range(self.iterations):
            if target_info["transport"] == "udp":
                status, elapsed = self.probe_quic_granular(ip)
            else:
                status, elapsed = self.probe_target_granular(target_info["url"])
                
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
            "errors": errors_summary
        }

    def run_parallel_tests(self, active_targets=None):
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
                        "errors": {"unknown_error": self.iterations}
                    }
        return results
    
    def probe_http_raw_granular(self, ip, host, port=80, timeout=3.0):
        """
        Отправляет сырой нешифрованный HTTP GET-запрос на порт 80
        и анализирует ответ на предмет перехвата и инжекции заглушек провайдеров.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        start_time = time.time()
        try:
            sock.connect((ip, port))
            # Формируем стандартный GET запрос к заблокированному ресурсу
            payload = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode('utf-8')
            sock.sendall(payload)
            response = sock.recv(4096)
            elapsed = (time.time() - start_time) * 1000.0
            
            resp_str = response.decode('utf-8', errors='ignore').lower()
            
            # Проверяем сигнатуры редиректов на заглушки российских провайдеров
            if "location:" in resp_str:
                # Фильтруем редиректы на известные домены блокировок провайдеров
                if any(kw in resp_str for kw in ["block", "warning", "warningpage", "rt.ru", "beeline", "mts.ru", "megafon", "dom.ru"]):
                    return "reset", elapsed # Рассматриваем редирект на заглушку как блокировку
            
            # Прямая инжекция HTML-кода блокировки
            if any(kw in resp_str for kw in ["zapret", "блокиров", "gosuslugi", "reestr", "rkn"]):
                return "reset", elapsed
                
            return "OK", elapsed
        except socket.timeout:
            elapsed = (time.time() - start_time) * 1000.0
            return "timeout", elapsed
        except (ConnectionResetError, ConnectionAbortedError):
            elapsed = (time.time() - start_time) * 1000.0
            return "reset", elapsed
        except Exception as e:
            elapsed = (time.time() - start_time) * 1000.0
            return self._classify_socket_error(e), elapsed
        finally:
            sock.close()

# Обновляем метод _probe_single_target для поддержки tcp_http транспорта:
    def _probe_single_target(self, name, target_info):
        successes = 0
        latencies = []
        errors_summary = {}
        
        parsed = urllib.parse.urlparse(target_info["url"])
        host = parsed.netloc
        
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror:
            ip = get_real_ip_via_doh(host)
            if not ip:
                return {
                    "name": name, "success_rate": 0.0, "avg_latency": 0.0, "latencies": [],
                    "errors": {"dns_error": self.iterations}
                }

        for _ in range(self.iterations):
            if target_info["transport"] == "udp":
                status, elapsed = self.probe_quic_granular(ip)
            elif target_info["transport"] == "tcp_http":
                # Вызов сырого HTTP/80 парсера
                status, elapsed = self.probe_http_raw_granular(ip, host)
            else:
                status, elapsed = self.probe_target_granular(target_info["url"])
                
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
            "errors": errors_summary
        }