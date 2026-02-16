@echo off
echo ============================================================
echo WebSec Framework - Servidor de Visualizacion
echo ============================================================
echo.
echo Deteniendo cualquier instancia previa de Flask...
taskkill /F /IM python.exe /FI "WINDOWTITLE eq *app.py*" 2>nul
timeout /t 2 /nobreak >nul
echo.
echo Iniciando servidor Flask...
echo.
python app.py
