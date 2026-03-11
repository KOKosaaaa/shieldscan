@echo off
chcp 65001 >nul 2>&1
title ShieldScan - Build Tool

echo ╔══════════════════════════════════════════╗
echo ║   ShieldScan .exe Builder                ║
echo ║   Сборка security_auditor в .exe         ║
echo ╚══════════════════════════════════════════╝
echo.

REM ── Check Python ──
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ОШИБКА] Python не найден! Установите Python 3.10+
    echo          https://python.org/downloads
    pause
    exit /b 1
)

echo [1/4] Python найден:
python --version
echo.

REM ── Install dependencies ──
echo [2/4] Установка зависимостей...
pip install pyinstaller rich --quiet
if %errorlevel% neq 0 (
    echo [ОШИБКА] Не удалось установить пакеты
    pause
    exit /b 1
)
echo       PyInstaller + Rich установлены
echo.

REM ── Check source file ──
if not exist "security_auditor.py" (
    echo [ОШИБКА] Файл security_auditor.py не найден!
    echo          Положите build.bat и security_auditor.py в одну папку
    pause
    exit /b 1
)

REM ── Build ──
echo [3/4] Компиляция в .exe (это займёт 1-2 минуты)...
echo.

pyinstaller ^
    --onefile ^
    --console ^
    --clean ^
    --name ShieldScan ^
    --icon NONE ^
    security_auditor.py

if %errorlevel% neq 0 (
    echo.
    echo [ОШИБКА] Компиляция провалилась
    pause
    exit /b 1
)

echo.
echo [4/4] Готово!
echo.
echo ╔══════════════════════════════════════════╗
echo ║  ShieldScan.exe собран успешно!          ║
echo ║                                          ║
echo ║  Файл: dist\ShieldScan.exe               ║
echo ║                                          ║
echo ║  Запуск:                                 ║
echo ║    Обычный:  ShieldScan.exe              ║
echo ║    С VT:     set VT_API_KEY=ключ         ║
echo ║              ShieldScan.exe              ║
echo ║    Экспорт:  ShieldScan.exe --export     ║
echo ║                                          ║
echo ║  Для полного скана запускайте             ║
echo ║  от имени администратора!                ║
echo ╚══════════════════════════════════════════╝
echo.

REM ── Copy to current dir for convenience ──
copy dist\ShieldScan.exe ShieldScan.exe >nul 2>&1

echo Файл скопирован в текущую папку: ShieldScan.exe
echo.
pause
