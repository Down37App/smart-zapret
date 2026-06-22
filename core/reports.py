# -*- coding: utf-8 -*-
import json
import time
import os
from core.blockcheck.scorer import StrategyScorer

class ReportGenerator:
    @staticmethod
    def save_json_report(filepath, leaderboard, duration_sec, dns_status="unknown"):
        """Экспорт структурированного JSON."""
        serialized_leaderboard = []
        for item in leaderboard:
            entry = {
                "strategy": item["strategy"].__dict__,
                "score": item["score"],
                "errors_summary": item["errors_summary"],
                "results": item["results"]
            }
            serialized_leaderboard.append(entry)

        report_data = {
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "dns_integrity_status": dns_status,
            "total_tested": len(leaderboard),
            "test_duration_seconds": round(duration_sec, 2),
            "leaderboard": serialized_leaderboard
        }
        try:
            os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(report_data, f, ensure_ascii=False, indent=2)
            print(f"[+] Отчет сохранен: {filepath}")
        except Exception as e:
            print(f"[-] Ошибка экспорта JSON: {e}")

    @staticmethod
    def explain_bypass_decisions(leaderboard, dns_status, tspu_hop):
        """
        Фаза C: Генерирует и выводит на экран подробное аналитическое объяснение 
        подобранного мультипрофильного обхода простым языком.
        """
        if not leaderboard:
            return

        best = leaderboard[0]["strategy"]
        best_score = leaderboard[0]["score"]
        
        dns_desc = "Чистый (системный DNS работает без вмешательства провайдера)."
        dns_advice = "Дополнительные DNS-профили не требуются."
        if dns_status == "poisoned":
            dns_desc = "ОТРАВЛЕН (провайдер подменяет IP-адреса заблокированных ресурсов)."
            dns_advice = "ВАЖНО: В сгенерированный скрипт внедрена автоматическая подмена DNS на зашифрованные сервера Cloudflare (1.1.1.1)."
        elif dns_status == "intercepted":
            dns_desc = "БЛОКИРУЕТСЯ / ПЕРЕХВАТЫВАЕТСЯ (UDP-порт 53 полностью закрыт провайдером)."
            dns_desc = "Вам рекомендуется использовать DNS-over-HTTPS (DoH) непосредственно в настройках браузера."

        print("\n" + "="*70)
        print("          АНАЛИТИЧЕСКИЙ ОТЧЕТ И СТАТИСТИКА ОБХОДА DPI")
        print("============================================================")
        print(f" [*] Сетевая дистанция до ТСПУ: {tspu_hop} хоп(ов).")
        print(f"     Инжектор провайдера находится очень близко. Фильтрация агрессивная.")
        print(f" [*] Состояние DNS (UDP 53)   : {dns_desc}")
        print(f"     {dns_advice}")
        print("-" * 70)
        print(" [*] ПОДБОР СТРАТЕГИЙ ПО СЕРВИСАМ:")
        
        # Разъяснение по YouTube
        print(f"\n  1. YouTube (TCP/UDP):")
        print(f"     - Подобран метод: {best.desc}")
        if "disorder" in best.mode:
            print("     - Физика обхода : Изменение порядка передачи TCP-сегментов (Disorder).")
            print("                       Сенсор DPI путается во временных буферах и пропускает поток.")
        elif "split" in best.mode:
            print("     - Физика обхода : Фрагментация TCP-потока (Split) на микро-сегменты.")
            print("                       DPI не успевает собрать SNI воедино для сигнатурного анализа.")
            
        # Разъяснение по сплит-позиции
        if best.split_pos == "midsld":
            print("     - Точка деления : Середина SNI (midsld). Разрезание доменного имени")
            print("                       пополам лишает DPI возможности распознать адрес.")
            
        # Разъяснение по Discord
        print(f"\n  2. Discord (Голосовые каналы / Голос):")
        print("     - Применен профиль: Инжекция фейковых UDP/QUIC-пакетов (QUIC Fake).")
        print("                         Маскирует голосовые каналы под трафик WebRTC/Stun.")
        
        # Разъяснение по общим сайтам
        print(f"\n  3. Обычные сайты (HTTP/HTTPS):")
        print("     - Применен профиль: Базовое разделение сегментов TLS ClientHello.")
        print("                         Обеспечивает легкий, бесперебойный доступ к веб-ресурсам.")
        print("============================================================\n")

    @staticmethod
    def save_text_summary(filepath, leaderboard, duration_sec, dns_status="unknown"):
        """Генерирует текстовую сводку в файл."""
        if not leaderboard:
            return

        best = leaderboard[0]["strategy"]
        best_score = leaderboard[0]["score"]
        best_errors = leaderboard[0]["errors_summary"]

        averages, best_of = StrategyScorer.analyze_success_factors(leaderboard)

        dns_desc = "Чистый"
        if dns_status == "poisoned":
            dns_desc = "ОТРАВЛЕН"
        elif dns_status == "intercepted":
            dns_desc = "БЛОКИРУЕТСЯ"

        lines = [
            "============================================================",
            "                WINDOWS BLOCKCHECK ANALYSIS SUMMARY         ",
            "============================================================",
            f" Время завершения: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            f" Продолжительность теста: {duration_sec:.1f} сек.",
            f" Проанализировано стратегий: {len(leaderboard)}",
            f" Состояние DNS-канала (UDP 53): {dns_desc}",
            "============================================================",
            "",
            "--- ОПТИМАЛЬНАЯ СТРАТЕГИЯ ОБХОДА ---",
            f" Название         : {best.desc}",
            f" Категория        : {best.category.upper()}",
            f" Эффективность    : {best_score:.1f}%",
            f" Ошибки на сокетах: {best_errors}",
            f" Строка nfqws/winws: {best.to_cmd('%BIN%')}",
            "",
            "--- АНАЛИЗ ПРИЧИН УСПЕХА (ЗНАЧИМОСТЬ СЕТЕВЫХ ПРИЗНАКОВ) ---",
            f"  * Лучший Режим (mode)      : {best_of['mode']['value']:12} (ср. стабильность {best_of['mode']['avg_score']:.1f}%)",
            f"  * Лучший Фокус (fooling)   : {best_of['fooling']['value']:12} (ср. стабильность {best_of['fooling']['avg_score']:.1f}%)",
            f"  * Лучший Сплит (split_pos) : {best_of['split_pos']['value']:12} (ср. стабильность {best_of['split_pos']['avg_score']:.1f}%)",
            f"  * Лучший TTL (autottl)     : {best_of['ttl']['value']:12} (ср. стабильность {best_of['ttl']['avg_score']:.1f}%)",
            "",
            "--- СРЕДНЯЯ СТАБИЛЬНОСТЬ ПО ПАРАМЕТРАМ ДЕСИНХРОНИЗАЦИИ ---"
        ]

        for dim, vals in averages.items():
            lines.append(f"  Вклад '{dim}':")
            for val, avg in vals.items():
                lines.append(f"    - {val:15} : {avg:.1f}% эффективности")

        lines.extend([
            "",
            "--- ТОП-5 ЛУЧШИХ СТРАТЕГИЙ ---",
            f" {'Место':5} | {'Категория':11} | {'Стабильность':12} | {'Параметры запуска'}"
        ])
        lines.append("-" * 80)

        for idx, item in enumerate(leaderboard[:5]):
            strat = item["strategy"]
            lines.append(f" {idx+1:5d} | {strat.category.upper():11} | {item['score']:11.1f}% | {strat.to_cmd('%BIN%')}")

        try:
            os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
        except Exception as e:
            print(f"[-] Ошибка экспорта текстового отчета: {e}")