:: regsave.bat - Saves to Results/RegSaver folder (no timestamps)
@echo off
setlocal enabledelayedexpansion

echo Windows Registry Backup Utility
echo ================================
echo.

:: Get the directory where this batch file is located (modules folder)
set "BATCH_DIR=%~dp0"

:: Navigate to main Python script directory (one level up)
cd /d "%BATCH_DIR%..\"

:: Create Results/RegSaver directory
set "BACKUP_DIR=Results\RegSaver"

:: Remove old backup if it exists and create fresh directory
if exist "%BACKUP_DIR%" (
    echo Removing old backup directory...
    rmdir /s /q "%BACKUP_DIR%" 2>nul
)

mkdir "%BACKUP_DIR%" 2>nul

if not exist "%BACKUP_DIR%" (
    echo ERROR: Cannot create backup directory: %BACKUP_DIR%
    echo Current directory: %cd%
    pause
    exit /b 1
)

echo Backup directory: %cd%\%BACKUP_DIR%
echo.

:: Set system paths
set "SystemRoot=C:\Windows"
set "PATH=%SystemRoot%\system32;%SystemRoot%;%PATH%"

:: Export standard registry keys
echo Exporting standard registry keys...
echo.

set "REG_KEYS=HKLM HKCU HKCR HKU HKCC"
for %%k in (%REG_KEYS%) do (
    echo [.] Exporting %%k...
    reg export %%k "%BACKUP_DIR%\%%k.reg" /y >nul 2>&1
    if errorlevel 1 (
        echo [!] Failed to export %%k
    ) else (
        echo [✓] Successfully exported %%k
    )
)

echo.
:: Check for admin rights
echo Checking privileges...
fltmc >nul 2>&1
if %errorlevel% equ 0 (
    echo [i] Administrative privileges detected.
    echo.
    
    echo Exporting protected registry hives...
    echo.
    
    set "PROTECTED_KEYS=SAM SECURITY SOFTWARE SYSTEM"
    for %%h in (%PROTECTED_KEYS%) do (
        echo [.] Exporting %%h...
        reg save HKLM\%%h "%BACKUP_DIR%\%%h.hiv" /y >nul 2>&1
        if errorlevel 1 (
            echo [!] Failed to export %%h
        ) else (
            echo [✓] Successfully exported %%h
        )
    )
    
    :: Export full registry to text
    echo.
    echo [.] Exporting full registry to text format...
    regedit /e "%BACKUP_DIR%\FullRegistry.txt" /a 2>nul
    if errorlevel 1 (
        echo [!] Failed to export full registry to text
    ) else (
        echo [✓] Successfully exported full registry
    )
    
    echo.
    echo [✓] COMPLETE backup finished!
) else (
    echo.
    echo [i] Standard backup completed (admin rights not available).
    echo [i] Run as Administrator for complete backup with SAM, SECURITY, etc.
)

echo.
echo =========================================
echo BACKUP COMPLETE
echo =========================================
echo Location: %cd%\%BACKUP_DIR%
echo.
echo Files created:
dir /b "%BACKUP_DIR%"
echo.
echo Total files created: 
dir /b "%BACKUP_DIR%" | find /c /v ""
echo.
pause
