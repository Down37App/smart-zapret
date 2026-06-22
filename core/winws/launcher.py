# -*- coding: utf-8 -*-
import subprocess
import time
import sys
import os
import signal

class WinwsLauncher:
    def __init__(self, engine_path):
        self.engine_path = os.path.abspath(engine_path).replace("\\", "/")
        self.process = None
        self.is_win = (sys.platform == "win32")

# -*- coding: utf-8 -*-
# Обновление метода _manage_linux_rules в файле core/winws/launcher.py:

# -*- coding: utf-8 -*-
# Изменение в файле core/winws/launcher.py (метод _manage_linux_rules):

    def _manage_linux_rules(self, action="-I"):
        """
        Управляет правилами iptables и ip6tables на Linux для перенаправления 
        трафика в очередь NFQUEUE 10 без утечки IPv6-пакетов.
        """
        if self.is_win:
            return
        
        # Настраиваем дублирующие правила для IPv4 и IPv6
        rules = [
            # IPv4
            f"iptables {action} OUTPUT -p tcp -m multiport --dports 80,443 -j NFQUEUE --queue-num 10 --queue-bypass",
            f"iptables {action} OUTPUT -p udp -m multiport --dports 443,19294:19344,50000:50100 -j NFQUEUE --queue-num 10 --queue-bypass",
            # IPv6 (Предотвращает утечку IPv6 в обход nfqws)
            f"ip6tables {action} OUTPUT -p tcp -m multiport --dports 80,443 -j NFQUEUE --queue-num 10 --queue-bypass",
            f"ip6tables {action} OUTPUT -p udp -m multiport --dports 443,19294:19344,50000:50100 -j NFQUEUE --queue-num 10 --queue-bypass"
        ]
        
        for rule in rules:
            try:
                subprocess.run(f"sudo {rule}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass

    def start(self, strategy_cmd, working_dir):
        """Запускает процесс winws (Windows) или nfqws (Linux) с автоматической настройкой фаервола."""
        self.stop()
        
        cmd_str = f'"{self.engine_path}" {strategy_cmd}'
        if self.is_win:
            cmd_str = cmd_str.replace("\\", "/")
            working_dir = os.path.abspath(working_dir).replace("\\", "/")
        else:
            # На Linux запускаем nfqws через sudo
            cmd_str = f"sudo {cmd_str}"
            # Настраиваем перехват пакетов в iptables перед стартом демона
            self._manage_linux_rules("-I")

        try:
            # На Linux запускаем процесс в отдельной сессии (PGID) для надежного убийства sudo-деревьев
            preexec = os.setsid if not self.is_win else None
            
            self.process = subprocess.Popen(
                cmd_str,
                shell=True,
                cwd=working_dir,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                preexec_fn=preexec,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if self.is_win else 0
            )
            time.sleep(0.8)
            poll = self.process.poll()
            if poll is not None:
                err_bytes = self.process.stderr.read()
                err_msg = err_bytes.decode('cp866', errors='ignore').strip()
                self._manage_linux_rules("-D") # Сбрасываем правила при вылете
                return False, f"Процесс завершился на старте (код {poll}). Ошибка: {err_msg}"
            
            return True, "Успешный запуск"
        except Exception as e:
            self._manage_linux_rules("-D")
            return False, str(e)

    def stop(self):
        """Убивает процесс и зачищает правила фаервола."""
        if self.is_win:
            try:
                subprocess.run("taskkill /F /IM winws.exe > nul 2>&1", shell=True)
            except Exception:
                pass
        else:
            # Сбрасываем правила iptables
            self._manage_linux_rules("-D")
            
            if self.process:
                # На Linux безопасно убиваем всю группу процессов (включая sudo-дочерние)
                try:
                    os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
                except Exception:
                    pass
                try:
                    # Чистим фоновые остатки nfqws, если они зависли в системе
                    subprocess.run("sudo killall -9 nfqws > /dev/null 2>&1", shell=True)
                except Exception:
                    pass
        self.process = None