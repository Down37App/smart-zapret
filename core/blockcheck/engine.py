# -*- coding: utf-8 -*-
import os
import json
import time
import sys
from core.winws.launcher import WinwsLauncher
from core.blockcheck.tester import NetworkTester
from core.blockcheck.scorer import StrategyScorer
from core.blockcheck.scheduler import AdaptiveStrategyScheduler
from core.blockcheck.strategies import Strategy
from core.telemetry import TelemetryLogger

CHECKPOINT_FILE = "blockcheck_checkpoint.json"

class BlockcheckEngine:
    def __init__(self, engine_path, working_dir):
        self.launcher = WinwsLauncher(engine_path)
        self.bin_dir = os.path.abspath(os.path.dirname(engine_path)).replace("\\", "/") + "/"
        self.working_dir = working_dir
        self.logger = TelemetryLogger()

    def save_checkpoint(self, phase, current_index, leaderboard, strategy_queue, phase_survivors):
        """Сохраняет состояние с полной сериализацией очередей и текущих результатов фазы."""
        serialized_queue = [s.__dict__ for s in strategy_queue]
        
        serialized_leaderboard = []
        for item in leaderboard:
            entry = dict(item)
            entry["strategy"] = item["strategy"].__dict__
            serialized_leaderboard.append(entry)

        serialized_survivors = []
        for item in phase_survivors:
            entry = {
                "strategy": item["strategy"].__dict__,
                "score": item["score"],
                "errors_summary": item["errors_summary"],
                "results": item["results"]
            }
            serialized_survivors.append(entry)

        state = {
            "phase": phase,
            "current_index": current_index,
            "leaderboard": serialized_leaderboard,
            "strategy_queue": serialized_queue,
            "phase_survivors": serialized_survivors
        }
        try:
            with open(CHECKPOINT_FILE, "w", encoding="utf-8") as f:
                json.dump(state, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"    [!] Ошибка записи чекпоинта: {e}")

    def load_checkpoint(self):
        """Загружает сессию и десериализует объекты с восстановлением прогресса фазы."""
        if os.path.exists(CHECKPOINT_FILE):
            try:
                with open(CHECKPOINT_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    
                deserialized_queue = [Strategy(**s) for s in data["strategy_queue"]]
                
                deserialized_leaderboard = []
                for item in data["leaderboard"]:
                    entry = dict(item)
                    entry["strategy"] = Strategy(**item["strategy"])
                    deserialized_leaderboard.append(entry)

                deserialized_survivors = []
                for item in data.get("phase_survivors", []):
                    entry = {
                        "strategy": Strategy(**item["strategy"]),
                        "score": item["score"],
                        "errors_summary": item["errors_summary"],
                        "results": item["results"]
                    }
                    deserialized_survivors.append(entry)

                data["strategy_queue"] = deserialized_queue
                data["leaderboard"] = deserialized_leaderboard
                data["phase_survivors"] = deserialized_survivors
                return data
            except Exception as e:
                print(f"[!] Чекпоинт поврежден: {e}. Начинаем с нуля.")
        return None

    def clear_checkpoint(self):
        if os.path.exists(CHECKPOINT_FILE):
            try:
                os.remove(CHECKPOINT_FILE)
            except Exception:
                pass

    def run_multiphase_flow(self, base_strategies, resume_state=None):
        """Управляет прохождением Фазы 1, Фазы 2 и Фазы 3 с авто-определением TTL."""
        leaderboard = resume_state["leaderboard"] if resume_state else []
        current_phase = resume_state["phase"] if resume_state else 1
        start_index = resume_state["current_index"] if resume_state else 0

        # Определение TTL и состояния DNS
        tspu_hop = None
        dns_status = "unknown"

        if not resume_state:
            print("\n[*] Инициализация датчиков: сканирование сетевого пути...")
            from core.diagnostics import detect_tspu_hop, analyze_dns_spoofing

            try:
                tspu_hop = detect_tspu_hop("www.youtube.com")
                if tspu_hop:
                    print(f"[+] Сетевой сенсор: ТСПУ обнаружен на расстоянии {tspu_hop} хопов.")
                else:
                    print("[-] Сетевой сенсор: Не удалось точно определить расстояние до ТСПУ.")
            except Exception as e:
                print(f"[!] Ошибка трассировки: {e}")

            print("[*] Инициализация датчиков: проверка целостности DNS (UDP 53)...")
            try:
                dns_status = analyze_dns_spoofing("discord.com", "8.8.8.8")
                if dns_status == "clean":
                    print("[+] DNS-сенсор: Подмена DNS не обнаружена. Канал чист.")
                elif dns_status == "poisoned":
                    print("[!] DNS-сенсор: ВНИМАНИЕ! Обнаружено отравление DNS (DNS Spoofing) со стороны провайдера.")
                elif dns_status == "intercepted":
                    print("[!] DNS-сенсор: ВНИМАНИЕ! Исходящие DNS-запросы (UDP 53) перехватываются или блокируются ТСПУ.")
            except Exception as e:
                print(f"[!] Ошибка DNS-анализа: {e}")

        self.dns_status = dns_status
        self.tspu_hop = tspu_hop

        # Настройка очередей
        if resume_state:
            active_queue = resume_state["strategy_queue"]
        else:
            active_queue = list(base_strategies)
            if tspu_hop:
                from core.blockcheck.strategies import StrategyManager
                calibrated_strats = StrategyManager.generate_calibrated_ttl_strategies(tspu_hop, self.bin_dir)
                if calibrated_strats:
                    print(f"[+] Auto TTL: Сгенерировано {len(calibrated_strats)} стратегий с точечным TTL.")
                    active_queue.extend(calibrated_strats)

        phase_config = {
            1: {
                "name": "Phase 1: Fast Scan [Отсев]", 
                "iters": 1, 
                "targets": ["YouTube TCP Main", "Discord TCP Website", "YouTube QUIC Main"]
            },
            2: {
                "name": "Phase 2: Verification Scan [Калибровка]", 
                "iters": 3, 
                "targets": ["YouTube TCP Main", "YouTube TCP CDN", "Discord TCP Website", "Discord TCP Gateway", "YouTube QUIC Main"]
            },
            3: {
                "name": "Phase 3: Deep Validation [Экспертиза]", 
                "iters": 5, 
                "targets": None  # Выбор абсолютно всех целей
            }
        }

        scheduler = AdaptiveStrategyScheduler()

        # Восстановление весов
        for item in leaderboard:
            scheduler.record_result(item["strategy"], item["score"])

        provider, asn = self.logger.get_network_info_cached()

        # Цикл фаз
        for phase_id in [1, 2, 3]:
            if phase_id < current_phase:
                continue

            scheduler.reset_phase_metrics()

            config = phase_config[phase_id]
            print("\n" + "="*60)
            print(f"    ЗАПУСК {config['name'].upper()}")
            print("="*60)

            from core.blockcheck.tester import DEFAULT_TARGETS
            if config["targets"]:
                phase_targets = {k: v for k, v in DEFAULT_TARGETS.items() if k in config["targets"]}
            else:
                phase_targets = DEFAULT_TARGETS

            if resume_state and phase_id == current_phase:
                phase_survivors = resume_state.get("phase_survivors", [])
                print(f"[+] Восстановлено {len(phase_survivors)} ранее протестированных стратегий данной фазы.")
            else:
                phase_survivors = []

            idx = start_index if phase_id == current_phase else 0
            
            while idx < len(active_queue):
                strat = active_queue[idx]
                
                run_targets = {}
                for k, v in phase_targets.items():
                    if strat.transport == "tcp" and v["transport"] in ["tcp", "tcp_http"]:
                        run_targets[k] = v
                    elif strat.transport == "udp" and v["transport"] == "udp":
                        run_targets[k] = v

                if not run_targets:
                    idx += 1
                    self.save_checkpoint(phase_id, idx, leaderboard, active_queue, phase_survivors)
                    continue

                print(f"    [{idx+1}/{len(active_queue)}] ({strat.transport.upper()} / {strat.category.upper()}) {strat.desc}...")

                tester = NetworkTester(targets=run_targets, iterations=config["iters"], bin_dir=self.bin_dir)

                cmd = strat.to_cmd(self.bin_dir)
                started, msg = self.launcher.start(cmd, self.working_dir)
                if not started:
                    print(f"        [-] Ошибка запуска winws.exe: {msg}")
                    idx += 1
                    self.save_checkpoint(phase_id, idx, leaderboard, active_queue, phase_survivors)
                    continue

                results = tester.run_parallel_tests()
                self.launcher.stop()

                score, errors = StrategyScorer.calculate_score(results)
                
                test_entry = {
                    "strategy": strat,
                    "score": score,
                    "errors_summary": errors,
                    "results": results
                }
                phase_survivors.append(test_entry)

                # ВЫСОКОЭНТРОПИЙНЫЙ СБОР ДАННЫХ ДЛЯ ИИ (Логируем АБСОЛЮТНО все попытки: и успехи, и провалы)
                try:
                    local_time = time.localtime()
                    # Парсим чистые числовые фичи с помощью strategies.py
                    ai_features = strat.parse_to_features(self.bin_dir, tspu_hop)
                    
                    features_dict = {
                        "strategy": ai_features,
                        "network_baseline": {
                            "tspu_distance_hops": tspu_hop,
                            "dns_integrity": dns_status
                        },
                        "environment": {
                            "local_hour": local_time.tm_hour,
                            "local_weekday": local_time.tm_wday,
                            "timezone_offset": time.altzone if local_time.tm_isdst > 0 else time.timezone
                        }
                    }
                    
                    targets_dict = {
                        "overall_score": score,
                        "phase_id": phase_id,
                        "probes": {}
                    }
                    for target_name, probe_res in results.items():
                        l7_symptom = "OK"
                        if probe_res["success_rate"] == 0:
                            l7_symptom = "SILENT_DROP"
                            if "reset" in probe_res["errors"]:
                                l7_symptom = "TCP_RESET"
                            elif "tls_error" in probe_res["errors"]:
                                l7_symptom = "TLS_ALERT"
                        
                        targets_dict["probes"][target_name] = {
                            "success_rate": probe_res["success_rate"],
                            "avg_latency": probe_res["avg_latency"],
                            "errors": probe_res["errors"],
                            "l7_symptom": l7_symptom,
                            "dns_resolved_ip": probe_res.get("dns_resolved_ip", "unknown"),
                            "handshake_phase_reached": probe_res.get("handshake_phase_reached", "resolve"),
                            "received_rst_from_dpi": probe_res.get("received_rst_from_dpi", False),
                            "response_ttl": probe_res.get("response_ttl")
                        }
                        
                    self.logger.log_ai_training_entry(
                        provider=provider,
                        asn=asn,
                        os_platform=sys.platform,
                        zapret_ver="3.1",
                        features_dict=features_dict,
                        targets_dict=targets_dict
                    )
                except Exception as e:
                    pass

                scheduler.record_result(strat, score)
                print(f"        -> Скор: {score:.1f}% | Ошибки: {errors}")

                # Адаптивное сжатие
                if phase_id == 2 and idx + 1 < len(active_queue):
                    remaining = active_queue[idx+1:]
                    active_queue = active_queue[:idx+1] + scheduler.prioritize_queue(remaining)
                
                idx += 1
                self.save_checkpoint(phase_id, idx, leaderboard, active_queue, phase_survivors)

            # Переходы между фазами
            phase_survivors.sort(key=lambda x: x["score"], reverse=True)
            
            if phase_id == 1:
                active_queue = [item["strategy"] for item in phase_survivors if item["score"] > 0]
                if not active_queue:
                    print("\n[!] Все стратегии отсеяны на Фазе 1. Сеть полностью заблокирована.")
                    self.clear_checkpoint()
                    return []
                print(f"\n[+] Фаза 1 пройдена. Во второй раунд выходят {len(active_queue)} стратегий.")
                
            elif phase_id == 2:
                active_queue = [item["strategy"] for item in phase_survivors[:5]]
                if not active_queue:
                    print("\n[!] Нет успешных кандидатов для финальной валидации.")
                    self.clear_checkpoint()
                    return []
                print(f"\n[+] Фаза 2 пройдена. В финал (Фаза 3) выходят топ-5 стратегий.")
                
            elif phase_id == 3:
                leaderboard = phase_survivors

        self.clear_checkpoint()
        return leaderboard