@echo off
chcp 65001 > nul
cd /d "%~dp0"
cd zapret_extracted\zapret-discord-youtube* 2>nul || cd zapret_extracted\zapret-discord-youtube
call custom_generated.bat
