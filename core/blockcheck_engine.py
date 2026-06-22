# -*- coding: utf-8 -*-
import os
import json

STRATEGIES_FILE = os.path.join("core", "strategies.json")

def get_blockcheck_strategies(bin_dir, is_windows=True, full_brute=False):
    """
    Генератор стратегий обхода.
    Если full_brute=False, считывает легкий список шаблонов.
    Если full_brute=True, динамически генерирует полную сетку из 120+ комбинаций
    параметров blockcheck.sh, отсекая несовместимые с ОС вылеты.
    """
    if not full_brute:
        # Быстрый экспертный подбор по базовым шаблонам
        if os.path.exists(STRATEGIES_FILE):
            try:
                with open(STRATEGIES_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass

        # Дефолтный короткий список шаблонов
        return [
            {"key": "split2_sniext", "desc": "Standard Split2 (sniext) [Базовое разделение сегментов]", "cmd": "--dpi-desync=split2 --dpi-desync-split-pos=sniext --dpi-desync-fooling=md5sig"},
            {"key": "split2_midsld", "desc": "Standard Split2 (midsld) [Сплит в середине SNI]", "cmd": "--dpi-desync=split2 --dpi-desync-split-pos=midsld --dpi-desync-fooling=md5sig"},
            {"key": "disorder_sniext", "desc": "TCP Disorder (sniext) [Перемешивание порядка пакетов TCP]", "cmd": "--dpi-desync=disorder --dpi-desync-split-pos=sniext --dpi-desync-fooling=badseq"},
            {"key": "disorder_midsld", "desc": "TCP Disorder (midsld) [Альтернативный порядок пакетов]", "cmd": "--dpi-desync=disorder --dpi-desync-split-pos=midsld --dpi-desync-fooling=badseq"},
            {"key": "fake_split2_sniext", "desc": "Fake TLS + Split2 (sniext) [Фейки и деление пакетов]", "cmd": "--dpi-desync=fake,split2 --dpi-desync-split-pos=sniext --dpi-desync-fooling=md5sig"},
            {"key": "fake_split2_midsld", "desc": "Fake TLS + Split2 (midsld) [Фейки и сплит SNI]", "cmd": "--dpi-desync=fake,split2 --dpi-desync-split-pos=midsld --dpi-desync-fooling=md5sig"},
            {"key": "split2_badsum_sniext", "desc": "Split2 + BadSum Fooling [Инжекция невалидных чексумм]", "cmd": "--dpi-desync=split2 --dpi-desync-split-pos=sniext --dpi-desync-fooling=badsum"},
            {"key": "multisplit_sniext", "desc": "Pure Multisplit (sniext) [Двойное деление TLS]", "cmd": "--dpi-desync=multisplit --dpi-desync-split-pos=sniext"},
            {"key": "multidisorder_midsld", "desc": "Pure Multidisorder (midsld) [Множественное перемешивание TCP]", "cmd": "--dpi-desync=multidisorder --dpi-desync-split-pos=2,midsld"},
            {"key": "wsize512_split2", "desc": "Window Size 512 + Split2 [Обрезка буфера сокета]", "cmd": "--wsize=512 --dpi-desync=fake,split2 --dpi-desync-split-pos=sniext --dpi-desync-fooling=md5sig"},
            {"key": "alt11_classic", "desc": "Flowseal Alt11 Classic (Fake+Multisplit + Overlap) [Сложное наложение]", "cmd": f'--dpi-desync=fake,multisplit --dpi-desync-split-seqovl=681 --dpi-desync-split-pos=1 --dpi-desync-fooling=ts --dpi-desync-repeats=8 --dpi-desync-split-seqovl-pattern="{bin_dir}tls_clienthello_www_google_com.bin" --dpi-desync-fake-tls="{bin_dir}tls_clienthello_www_google_com.bin"'}
        ]

    # --- ДИНАМИЧЕСКИЙ ГЕНЕРАТОР ПОЛНОГО СПИСКА СТРАТЕГИЙ BLOCKCHECK ---
    desync_modes = ["split2", "disorder", "multisplit", "multidisorder", "fake,split2", "fake,disorder"]
    split_positions = ["sniext", "midsld", "1", "2"]
    fooling_modes = ["none", "md5sig", "badsum", "badseq", "ts"]
    
    # Резервные авто-ttl дельты для глубокого анализа ТСПУ
    autottl_modes = [
        "", 
        " --dpi-desync-ttl=1 --dpi-desync-autottl=-1", 
        " --dpi-desync-ttl=1 --dpi-desync-autottl=-3"
    ]

    generated_strategies = []
    idx = 1
    
    for mode in desync_modes:
        for pos in split_positions:
            for fooling in fooling_modes:
                for attl in autottl_modes:
                    # Исключаем несовместимые с Windows/winws синтаксические варианты во избежание вылетов
                    if "disorder" in mode and "split" in mode:
                        continue # winws не поддерживает комбинацию disorder+split в одном параметре
                        
                    fool_cmd = f" --dpi-desync-fooling={fooling}" if fooling != "none" else ""
                    pos_cmd = f" --dpi-desync-split-pos={pos}"
                    
                    cmd = f"--dpi-desync={mode}{pos_cmd}{fool_cmd}{attl}"
                    
                    generated_strategies.append({
                        "key": f"gen_strategy_{idx}",
                        "desc": f"Синтезированный тест #{idx} (mode={mode}, pos={pos}, fool={fooling})",
                        "cmd": cmd.strip()
                    })
                    idx += 1
                    
    return generated_strategies