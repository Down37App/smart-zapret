@echo off
chcp 65001 > nul
cd /d "%~dp0"

:: Проверка прав Администратора
net session >nul 2>&1 || (echo [!] Ошибка: Пожалуйста, запустите этот BAT-файл от имени Администратора! & pause & exit /b)

set "BIN=%~dp0bin\"
set "LISTS=%~dp0lists\"
cd /d %BIN%

echo [*] Подготовка сети: временная установка DNS 1.1.1.1 на всех активных адаптерах...
powershell -Command "Get-NetIPInterface -ConnectionState Connected -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike '*Loopback*' } | ForEach-Object { Set-DnsClientServerAddress -InterfaceAlias $_.InterfaceAlias -ServerAddresses ('1.1.1.1', '8.8.8.8') }"
ipconfig /flushdns > nul

echo [*] Запуск выделенного обхода Discord (pure_multidisorder)...
start "zapret: discord_custom" /min "%BIN%winws.exe" ^
  --wf-tcp=443,2053,2083,2087,2096,8443 ^
  --wf-udp=443,19294-19344,50000-50100 ^
  --filter-udp=19294-19344,50000-50100 --filter-l7=discord,stun --dpi-desync=fake --dpi-desync-fake-discord="%BIN%quic_initial_dbankcloud_ru.bin" --dpi-desync-fake-stun="%BIN%quic_initial_dbankcloud_ru.bin" --dpi-desync-repeats=6 --new ^
  --filter-tcp=2053,2083,2087,2096,8443 --hostlist-domains=discord.media --dpi-desync=multidisorder --dpi-desync-split-pos=2,midsld --new ^
  --filter-tcp=443 --hostlist="%LISTS%list-discord.txt" --dpi-desync=multidisorder --dpi-desync-split-pos=2,midsld

echo [+] Специализированный обход Discord успешно запущен в фоновом режиме.
echo [!] Для ОСТАНОВКИ обхода и автоматического восстановления исходного DNS нажмите любую клавишу...
pause

echo [*] Восстановление исходных системных настроек DNS...
powershell -Command "Get-NetIPInterface -ConnectionState Connected -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike '*Loopback*' } | Set-DnsClientServerAddress -ResetServerAddresses"
ipconfig /flushdns > nul

echo [*] Завершение процессов winws...
taskkill /F /IM winws.exe > nul 2>&1
echo [+] Сетевые настройки и процессы успешно восстановлены.
