:: modules\weak-permissions.bat  
@echo off
echo [📁] Scanning for weak filesystem permissions...

:: Check for Everyone/Full Control on sensitive directories
for %%d in (
    "C:\Windows\Temp"
    "C:\Windows\Tasks"
    "C:\Windows\System32\spool\drivers"
    "%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
) do (
    icacls "%%~d" 2>nul | findstr /i "(Everyone|Authenticated Users).*\(F\)" && (
        echo ⚠️ Weak permissions on: %%~d
    )
)

:: Check service permissions (weak DACLs)
echo.
echo [⚙️] Checking service permissions...
sc query | findstr "SERVICE_NAME" > services.tmp
for /f "tokens=2 delims=:" %%s in (services.tmp) do (
    sc sdshow %%s 2>nul | findstr "WD.*GA" && echo ⚠️ Weak DACL on service: %%s
)
del services.tmp