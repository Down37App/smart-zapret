# -*- coding: utf-8 -*-
import os
import sys
import time

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.diagnostics import (
    is_admin, get_active_interfaces, set_custom_dns, restore_dns
)
from core.blockcheck.strategies import StrategyManager, Strategy
from core.blockcheck.engine import BlockcheckEngine, CHECKPOINT_FILE
from core.reports import ReportGenerator
from core.profiles import MultiServiceGenerator

def print_banner():
    print("""
============================================================
      SMART ZAPRET AUTOMATION & WINDOWS BLOCKCHECK v3.1
============================================================
    """)

def check_environment():
    if not is_admin():
        print("[!] Ошибка: Для запуска требуются права Администратора (root в Linux)!")
        input("Нажмите Enter для выхода...")
        sys.exit(1)

def check_existing_scripts():
    """Проверяет наличие готового сценария обхода и предлагает запустить его."""
    is_win = (sys.platform == "win32")
    script_name = "custom_generated.bat" if is_win else "custom_generated.sh"
    
    if os.path.exists(script_name):
        print(f"\n[+] ОБНАРУЖЕН ГОТОВЫЙ СЦЕНАРИЙ ОБХОДА: {script_name}")
        choice = input("Запустить этот обход прямо сейчас? (y/n): ").strip().lower()
        if choice in ["y", "yes", ""]:
            print(f"[*] Запуск {script_name}...")
            try:
                if is_win:
                    os.system(f"start {script_name}")
                else:
                    os.system(f"sudo ./{script_name}")
                sys.exit(0)
            except Exception as e:
                print(f"[-] Не удалось запустить скрипт обхода: {e}")

def run_active_bypass_diagnostics():
    """
    Пункт 4: Реализует независимую диагностику активного обхода на чистых сокетах.
    Проверяет доступность всех ключевых сетевых целей в реальном времени.
    """
    print("\n" + "="*70)
    print("          ВЕРИФИКАЦИЯ АКТИВНОГО ОБХОДА (ДИАГНОСТИКА ДОСТУПНОСТИ)")
    print("============================================================")
    print("[*] Сетевой тестер проводит серию реальных сокет-запросов...")
    print("[*] Пожалуйста, убедитесь, что ваш скрипт обхода (sh/bat) сейчас запущен!")
    print("-" * 70)
    
    from core.blockcheck.tester import NetworkTester
    # Запуск параллельного тестирования на 3 итерации
    tester = NetworkTester(iterations=3)
    results = tester.run_parallel_tests()
    
    success_count = 0
    total_count = len(results)
    
    for name, res in results.items():
        rate = res["success_rate"]
        avg_lat = res["avg_latency"]
        errors = res["errors"]
        
        if rate >= 80.0:
            status_text = f"[УСПЕШНО] (Доступен, пинг {avg_lat:.1f} мс)"
            success_count += 1
        elif rate > 0.0:
            status_text = f"[НЕСТАБИЛЬНО] (Доступность {rate:.1f}%, пинг {avg_lat:.1f} мс)"
            success_count += 1
        else:
            err_desc = list(errors.keys())[0] if errors else "timeout"
            status_text = f"[БЛОКИРОВАН] (Ошибка: {err_desc})"
            
        print(f"  [*] {name:20} : {status_text}")
        
    print("-" * 70)
    overall_rate = (success_count / total_count) * 100.0
    print(f" [+] Результат: Пройдено {success_count} из {total_count} тестов (Эффективность: {overall_rate:.1f}%)")
    
    if overall_rate == 100.0:
        print("\n [+][+] Отлично! Ваш мультипрофильный обход полностью разблокировал все ресурсы!")
    elif overall_rate >= 50.0:
        print("\n [!] Предупреждение: Обход работает частично. Некоторые домены все еще заблокированы.")
        print("     Рекомендуется запустить Глубокий подбор (Пункт 2), чтобы подобрать более пробивные стратегии.")
    else:
        print("\n [-] Критическая блокировка: Активный обход не работает на вашей сети.")
        print("     Провайдер полностью блокирует TCP/UDP сессии. Запустите Глубокий подбор (Пункт 2).")
    print("============================================================\n")
    input("Нажмите Enter для возврата в меню...")

def run_blockcheck_flow(full_brute=False):
    # Автоопределение nfqws/winws
    if sys.platform == "win32":
        engine_path = "zapret_extracted/zapret-discord-youtube-master/bin/winws.exe"
        if not os.path.exists(engine_path):
            for root, dirs, files in os.walk("zapret_extracted"):
                if "winws.exe" in files:
                    engine_path = os.path.join(root, "winws.exe")
                    break
    else:
        engine_path = "nfqws"
        for path in ["/opt/zapret/nfqws/nfqws", "./zapret/nfqws/nfqws", "/usr/bin/nfqws", "/usr/local/bin/nfqws", "/opt/zapret/nfq/nfqws"]:
            if os.path.exists(path):
                engine_path = path
                break
        
        if not engine_path:
            print("\n[-] КРИТИЧЕСКАЯ ОШИБКА: Демон nfqws не найден в вашей Linux-системе!")
            print("============================================================")
            print("Для работы Blockcheck на Linux требуется установленный nfqws.")
            print("Пожалуйста, выполните установку оригинального zapret:")
            print("  1. git clone https://github.com/bol-van/zapret.git")
            print("  2. cd zapret && sudo ./install_easy.sh")
            print("============================================================")
            input("\nНажмите Enter для возврата в меню...")
            return

    working_dir = os.path.dirname(os.path.dirname(engine_path))
    if not working_dir or working_dir == "/opt/zapret" or working_dir == "/opt/zapret/nfq":
        working_dir = "." # Защита корневой директории
        
    interfaces = get_active_interfaces()
    if interfaces:
        set_custom_dns(interfaces, "1.1.1.1")
        time.sleep(1)

    try:
        engine = BlockcheckEngine(engine_path, working_dir)
        
        resume_state = None
        if os.path.exists(CHECKPOINT_FILE):
            checkpoint = engine.load_checkpoint()
            if checkpoint:
                print(f"\n[!] ОБНАРУЖЕН ПРЕРВАННЫЙ СЕАНС (Фаза {checkpoint['phase']}, индекс: {checkpoint['current_index'] + 1})")
                ans = input("Желаете продолжить подбор с момента прерывания? (y/n): ").strip().lower()
                if ans in ["y", "yes", ""]:
                    resume_state = checkpoint
                    print("[+] Возобновление сессии...")

        if resume_state:
            strategies = resume_state["strategy_queue"]
        else:
            engine.clear_checkpoint()
            if full_brute:
                strategies = StrategyManager.generate_full_grid()
            else:
                bin_dir = os.path.abspath(os.path.dirname(engine_path)).replace("\\", "/") + "/"
                strategies = StrategyManager.get_default_templates(bin_dir)

        start_time = time.time()
        leaderboard = engine.run_multiphase_flow(strategies, resume_state=resume_state)
        duration = time.time() - start_time

        if not leaderboard:
            print("\n[-] Не удалось подобрать рабочие варианты десинхронизации.")
            return

        # Нахождение лучшей общей стратегии
        champion = leaderboard[0]["strategy"]
        dns_status = getattr(engine, "dns_status", "unknown")
        tspu_hop = getattr(engine, "tspu_hop", "1")

        # Интеллектуальный разбор победителей по сервисам (для генератора мультипрофилей)
        best_yt, best_discord, best_general = None, None, None
        for item in leaderboard:
            strat = item["strategy"]
            score = item["score"]
            if score > 0:
                if not best_yt and (strat.mode in ["fake,multisplit", "multidisorder"] or "google" in strat.desc.lower()):
                    best_yt = strat
                if not best_discord and (strat.transport == "udp" or "discord" in strat.desc.lower()):
                    best_discord = strat
                if not best_general and (strat.mode in ["split2", "disorder"] or "general" in strat.desc.lower()):
                    best_general = strat

        best_yt = best_yt or champion
        best_discord = best_discord or champion
        best_general = best_general or champion

        # Фаза C: Понятное объяснение решений на экране
        ReportGenerator.explain_bypass_decisions(leaderboard, dns_status, tspu_hop)

        # Сохранение классических отчетов
        reports_dir = "blockcheck_reports"
        json_path = os.path.join(reports_dir, "report.json")
        txt_path = os.path.join(reports_dir, "summary.txt")
        
        ReportGenerator.save_json_report(json_path, leaderboard, duration, dns_status)
        ReportGenerator.save_text_summary(txt_path, leaderboard, duration, dns_status)

        # Сборка мультипрофильного скрипта обхода
        script_ext = "bat" if sys.platform == "win32" else "sh"
        save_choice = input(f"\nСгенерировать мультисервисный сценарий обхода (custom_generated.{script_ext})? (y/n): ").strip().lower()
        if save_choice in ["y", "yes", ""]:
            generator = MultiServiceGenerator(lists_dir="./lists")
            success = generator.generate_files(
                best_yt=best_yt,
                best_discord=best_discord,
                best_general=best_general,
                bin_dir=os.path.dirname(engine_path),
                output_dir="." # Сохраняем прямо в корень проекта для автообнаружения!
            )
            if success:
                print(f"[+] Сценарий обхода успешно записан в корень проекта!")

    finally:
        if interfaces:
            restore_dns()

def main_menu():
    print_banner()
    check_environment()
    check_existing_scripts() # Автозапуск при обнаружении готовых обходов!

    is_win = (sys.platform == "win32")
    script_name = "custom_generated.bat" if is_win else "custom_generated.sh"

    while True:
        print("\nВыберите тип анализа или действие:")
        print("1. Быстрый многофазный подбор (экспертные шаблоны)")
        print("2. Глубокий многофазный перебор всей сетки DPI (120+ комбинаций)")
        print(f"3. Запустить ранее сгенерированный обход ({script_name})")
        print(f"4. Проверить работу запущенного обхода (Тест доступности YouTube/Discord)")
        print("5. Выход")

        choice = input("\nВвод (1-5): ").strip()
        if choice == "1":
            run_blockcheck_flow(full_brute=False)
        elif choice == "2":
            run_blockcheck_flow(full_brute=True)
        elif choice == "3":
            if os.path.exists(script_name):
                print(f"\n[*] Запуск {script_name}...")
                try:
                    if is_win:
                        os.system(f"start {script_name}")
                    else:
                        # Запуск нативного Linux сценария с перехватом трафика
                        os.system(f"sudo ./{script_name}")
                    sys.exit(0)
                except Exception as e:
                    print(f"[-] Не удалось запустить скрипт обхода: {e}")
            else:
                print(f"\n[-] Скрипт обхода {script_name} еще не создан.")
                print("[*] Пожалуйста, выполните быстрый (1) или глубокий (2) подбор для его автоматической генерации.")
        elif choice == "4":
            run_active_bypass_diagnostics() # Проверка активного обхода на чистых сокетах!
        elif choice == "5":
            print("[*] Завершение работы.")
            break
        else:
            print("[-] Ошибка ввода.")

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n[!] Выход.")
        sys.exit(0)