@echo off
chcp 65001 > nul
cd /d "%~dp0"
echo [*] Запуск подобранного обхода DPI (Синтез #209 (mode=multidisorder, pos=midsld, fool=ts, ttl=1))...
start "zapret: custom" /min "%~dp0bin/winws.exe" --wf-tcp=80,443 --filter-tcp=80,443 --dpi-desync=multidisorder --dpi-desync-split-pos=midsld --dpi-desync-fooling=ts --dpi-desync-ttl=1
echo [+] Обход активен.
pause
