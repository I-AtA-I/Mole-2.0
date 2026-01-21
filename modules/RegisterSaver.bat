:: save-all-registry.bat
@echo off
setlocal enabledelayedexpansion

echo Saving Windows Registry Hives...
echo.

:: Set output directory
set "BACKUP_DIR=%USERPROFILE%\Desktop\RegistryBackup_%date:~-4,4%%date:~-10,2%%date:~-7,2%"
mkdir "%BACKUP_DIR%" 2>nul

echo Exporting standard registry hives to %BACKUP_DIR%
echo.

:: Export standard hives
reg export HKLM "%BACKUP_DIR%\HKLM.reg" /y
reg export HKCU "%BACKUP_DIR%\HKCU.reg" /y
reg export HKCR "%BACKUP_DIR%\HKCR.reg" /y
reg export HKU "%BACKUP_DIR%\HKU.reg" /y
reg export HKCC "%BACKUP_DIR%\HKCC.reg" /y

:: Export SAM, SECURITY, SOFTWARE, SYSTEM (requires admin)
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Administrative privileges required for some hives.
    echo Run as administrator for complete backup.
    pause
    exit /b 1
)

:: These are loaded hives - export via reg save command
reg save HKLM\SAM "%BACKUP_DIR%\SAM.hiv" /y
reg save HKLM\SECURITY "%BACKUP_DIR%\SECURITY.hiv" /y
reg save HKLM\SOFTWARE "%BACKUP_DIR%\SOFTWARE.hiv" /y
reg save HKLM\SYSTEM "%BACKUP_DIR%\SYSTEM.hiv" /y

:: Export to text format for easier reading
regedit /e "%BACKUP_DIR%\FullRegistry.txt" /a

echo.
echo [✓] Registry export completed!
echo Location: %BACKUP_DIR%
echo.
echo Files created:
echo - HKLM.reg, HKCU.reg, HKCR.reg, HKU.reg, HKCC.reg (REG format)
echo - SAM.hiv, SECURITY.hiv, SOFTWARE.hiv, SYSTEM.hiv (HIV format)
echo - FullRegistry.txt (text format)
echo.
pause
