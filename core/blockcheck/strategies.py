# -*- coding: utf-8 -*-
import os
import sys

def find_fake_file(filename, bin_dir):
    """Рекурсивно ищет файлы фейков (.bin). Возвращает None, если файлы не найдены."""
    path = os.path.join(bin_dir, filename).replace("\\", "/")
    if os.path.exists(path):
        return path
        
    common_roots = ["/opt/zapret", "./zapret", "./zapret_extracted", "/usr/share/zapret", "."]
    for root in common_roots:
        if os.path.exists(root):
            for dirpath, dirnames, filenames in os.walk(root):
                if filename in filenames:
                    return os.path.abspath(os.path.join(dirpath, filename)).replace("\\", "/")
    
    # СТРОГО: Возвращаем None, если файл отсутствует в системе
    return None


class Strategy:
    def __init__(self, key, desc, mode, fooling, split_pos, ttl=None, repeats=None, custom_args="", category="fast", transport="tcp"):
        self.key = key
        self.desc = desc
        self.mode = mode               # split2, disorder, fake и т.д.
        self.fooling = fooling         # md5sig, badseq, badsum, ts, none
        self.split_pos = split_pos     # sniext, midsld, 1, 2, None
        self.ttl = ttl                 # int или None
        self.repeats = repeats         # int или None
        self.custom_args = custom_args # Дополнительные бинарники, файлы и т.д.
        self.category = category       # fast, recommended, aggressive, experimental
        self.transport = transport     # tcp, udp, tcp_http

    def to_cmd(self, bin_dir="", raw_desync_only=False):
        """Генерирует параметры запуска с мягким пропуском отсутствующих слепков фейков."""
        parts = []
        is_win = (sys.platform == "win32")
        
        if not raw_desync_only:
            if is_win:
                if self.transport == "udp":
                    parts.append("--wf-udp=443 --filter-udp=443")
                else:
                    parts.append("--wf-tcp=80,443 --filter-tcp=80,443")
            else:
                parts.append("--qnum=10")

        if self.mode:
            parts.append(f"--dpi-desync={self.mode}")
        if self.split_pos:
            parts.append(f"--dpi-desync-split-pos={self.split_pos}")
        if self.fooling and self.fooling != "none":
            parts.append(f"--dpi-desync-fooling={self.fooling}")
        if self.ttl is not None:
            parts.append(f"--dpi-desync-ttl={self.ttl}")
        if self.repeats is not None:
            parts.append(f"--dpi-desync-repeats={self.repeats}")
        if self.custom_args:
            resolved = self.custom_args
            
            # Если файл-слепок TLS ClientHello отсутствует, вырезаем этот аргумент
            if "tls_clienthello_www_google_com.bin" in resolved:
                real_path = find_fake_file("tls_clienthello_www_google_com.bin", bin_dir)
                if real_path:
                    resolved = resolved.replace('"{bin}tls_clienthello_www_google_com.bin"', f'"{real_path}"')
                else:
                    resolved = resolved.replace('--dpi-desync-fake-tls="{bin}tls_clienthello_www_google_com.bin"', '')
                    resolved = resolved.replace('--dpi-desync-split-seqovl-pattern="{bin}tls_clienthello_www_google_com.bin"', '')
            
            # Если файл-слепок QUIC Initial отсутствует, вырезаем этот аргумент
            if "quic_initial_www_google_com.bin" in resolved:
                real_path = find_fake_file("quic_initial_www_google_com.bin", bin_dir)
                if real_path:
                    resolved = resolved.replace('"{bin}quic_initial_www_google_com.bin"', f'"{real_path}"')
                else:
                    resolved = resolved.replace('--dpi-desync-fake-quic="{bin}quic_initial_www_google_com.bin"', '')
                    
            parts.append(resolved)
                
        return " ".join(parts)


class StrategyManager:
    @staticmethod
    def get_default_templates(bin_dir):
        """Возвращает структурированные объекты стратегий."""
        return [
            Strategy(
                key="split2_sniext",
                desc="Standard Split2 (sniext) [Базовое деление]",
                mode="split2", fooling="md5sig", split_pos="sniext",
                category="fast"
            ),
            Strategy(
                key="disorder_sniext",
                desc="TCP Disorder (sniext) [Перемешивание пакетов]",
                mode="disorder", fooling="badseq", split_pos="sniext",
                category="fast"
            ),
            Strategy(
                key="fake_split2_sniext",
                desc="Fake TLS + Split2 (sniext) [Фейки + деление]",
                mode="fake,split2", fooling="md5sig", split_pos="sniext",
                category="recommended"
            ),
            Strategy(
                key="split2_badsum_sniext",
                desc="Split2 + BadSum Fooling [Невалидные чексуммы]",
                mode="split2", fooling="badsum", split_pos="sniext",
                category="aggressive"
            ),
            Strategy(
                key="multisplit_sniext",
                desc="Pure Multisplit (sniext) [Двойное деление TLS]",
                mode="multisplit", fooling="none", split_pos="sniext",
                category="aggressive"
            ),
            Strategy(
                key="alt11_classic",
                desc="Flowseal Alt11 Classic (Fake+Multisplit) [Сложная десинхронизация]",
                mode="fake,multisplit", fooling="ts", split_pos="1", repeats=8,
                custom_args='--dpi-desync-split-seqovl=681 --dpi-desync-split-seqovl-pattern="{bin}tls_clienthello_www_google_com.bin" --dpi-desync-fake-tls="{bin}tls_clienthello_www_google_com.bin"',
                category="recommended"
            ),
            Strategy(
                key="wsize512_split2",
                desc="Window Size 512 + Split2 [Зажим окна сокета]",
                mode="fake,split2", fooling="md5sig", split_pos="sniext",
                custom_args="--wsize=512",
                category="experimental"
            ),
            Strategy(
                key="quic_fake_classic",
                desc="QUIC UDP Fake [Обход HTTP/3 YouTube]",
                mode="fake", fooling="none", split_pos=None, repeats=6,
                custom_args='--dpi-desync-fake-quic="{bin}quic_initial_www_google_com.bin"',
                category="recommended",
                transport="udp"
            ),
            Strategy(
                key="quic_fake_custom_repeats",
                desc="QUIC UDP Fake (11 repeats) [Агрессивный QUIC обход]",
                mode="fake", fooling="none", split_pos=None, repeats=11,
                custom_args='--dpi-desync-fake-quic="{bin}quic_initial_www_google_com.bin"',
                category="aggressive",
                transport="udp"
            ),
            Strategy(
                key="http_extra_space",
                desc="HTTP Extra Space [Обход заголовков HTTP/80]",
                mode="split2", fooling="md5sig", split_pos="sniext",
                custom_args="--http-extra-space",
                category="recommended",
                transport="tcp"
            )
        ]

    @staticmethod
    def generate_full_grid():
        """Синтезирует комбинаторную объектную сетку параметров."""
        desync_modes = ["split2", "disorder", "multisplit", "multidisorder", "fake,split2", "fake,disorder"]
        split_positions = ["sniext", "midsld", "1", "2"]
        fooling_modes = ["none", "md5sig", "badsum", "badseq", "ts"]
        ttls = [None, 1, 3]

        strategies = []
        idx = 1
        for mode in desync_modes:
            for pos in split_positions:
                for fooling in fooling_modes:
                    for ttl in ttls:
                        if "disorder" in mode and "split" in mode:
                            continue

                        if mode in ["split2", "disorder"] and fooling in ["none", "md5sig"] and ttl is None:
                            cat = "fast"
                        elif "fake" in mode:
                            cat = "recommended"
                        elif fooling in ["badsum", "badseq"]:
                            cat = "aggressive"
                        else:
                            cat = "experimental"

                        strategies.append(Strategy(
                            key=f"gen_strategy_{idx}",
                            desc=f"Синтез #{idx} (mode={mode}, pos={pos}, fool={fooling})",
                            mode=mode, fooling=fooling, split_pos=pos, ttl=ttl,
                            category=cat, transport="tcp"
                        ))
                        idx += 1
                        
        # Добавляем нативные UDP стратегии в конец полной сетки
        strategies.append(Strategy(
            key="gen_strategy_quic_1",
            desc="QUIC UDP Fake [Обход HTTP/3 YouTube]",
            mode="fake", fooling="none", split_pos=None, repeats=6,
            custom_args='--dpi-desync-fake-quic="{bin}quic_initial_www_google_com.bin"',
            category="recommended", transport="udp"
        ))
        strategies.append(Strategy(
            key="gen_strategy_quic_2",
            desc="QUIC UDP Fake (11 repeats) [Агрессивный QUIC обход]",
            mode="fake", fooling="none", split_pos=None, repeats=11,
            custom_args='--dpi-desync-fake-quic="{bin}quic_initial_www_google_com.bin"',
            category="aggressive", transport="udp"
        ))
        
        return strategies

    @staticmethod
    def generate_calibrated_ttl_strategies(tspu_hop, bin_dir=""):
        """Динамически генерирует набор стратегий, адаптированных под расстояние до ТСПУ."""
        if not tspu_hop or tspu_hop < 2:
            return []

        calibrated_ttls = []
        if tspu_hop > 1:
            calibrated_ttls.append(tspu_hop - 1)
        if tspu_hop > 2:
            calibrated_ttls.append(tspu_hop - 2)
        calibrated_ttls.append(tspu_hop)

        dynamic_strats = []
        idx = 1
        for ttl_val in calibrated_ttls:
            dynamic_strats.append(Strategy(
                key=f"ttl_split_delta_{idx}",
                desc=f"Calibrated TTL ({ttl_val}) + Split2 sniext",
                mode="fake,split2", fooling="md5sig", split_pos="sniext", ttl=ttl_val,
                category="recommended", transport="tcp"
            ))
            dynamic_strats.append(Strategy(
                key=f"ttl_disorder_delta_{idx}",
                desc=f"Calibrated TTL ({ttl_val}) + TCP Disorder sniext",
                mode="fake,disorder", fooling="badseq", split_pos="sniext", ttl=ttl_val,
                category="recommended", transport="tcp"
            ))
            idx += 1
            
        return dynamic_strats