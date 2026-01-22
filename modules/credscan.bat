:: weak-permissions.bat - Saves formatted JSON to Results/CredScan
@echo off
setlocal enabledelayedexpansion

echo WEAK PERMISSIONS SCANNER
echo -------------------------
echo.

:: Set system paths
set "SystemRoot=C:\Windows"
set "PATH=%SystemRoot%\system32;%SystemRoot%;%PATH%"

:: Set output directory
set "MAIN_DIR=%~dp0..\"
cd /d "%MAIN_DIR%"
set "OUTPUT_DIR=Results\CredScan"
mkdir "%OUTPUT_DIR%" 2>nul
set "JSON_FILE=%OUTPUT_DIR%\scan_results.json"

:: Initialize variables for JSON
set "JSON_LINES=0"
set "TEMP_FILE=%TEMP%\json_temp.txt"

:: Start building JSON file
(
echo {
echo   "scan_type": "weak_permissions",
echo   "timestamp": "%date% %time%",
echo   "issues_found": 0,
echo   "categories": {
echo     "filesystem_issues": [
) > "%TEMP_FILE%"

:: ------------------------------------------------------------------
:: PART 1: Check for weak filesystem permissions
:: ------------------------------------------------------------------
echo [1] Scanning for weak filesystem permissions...
echo.

set "WEAK_COUNT=0"
set "SENSITIVE_DIRS=C:\Windows\Temp|C:\Windows\Tasks|C:\Windows\System32\spool\drivers|C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
set "FIRST_FS=1"

for /f "tokens=1-4 delims=|" %%a in ("%SENSITIVE_DIRS%") do (
    for %%d in (%%a %%b %%c %%d) do (
        if not "%%d"=="" (
            echo Checking: %%d
            icacls "%%d" 2>nul | findstr /i "(Everyone|Authenticated Users|BUILTIN\\Users).*(F|M|W|D|DC)" >nul
            if !errorlevel! equ 0 (
                echo [WARNING] Weak permissions found on: %%d
                set /a WEAK_COUNT+=1
                
                :: Add to JSON
                if !FIRST_FS! equ 1 (
                    echo       {"path": "%%d", "issue": "weak_permissions"}" >> "%TEMP_FILE%"
                    set "FIRST_FS=0"
                ) else (
                    echo       ,{"path": "%%d", "issue": "weak_permissions"}" >> "%TEMP_FILE%"
                )
            )
        )
    )
)

:: Close filesystem array and start service array
echo     ],
echo     "service_issues": [
) >> "%TEMP_FILE%"

:: ------------------------------------------------------------------
:: PART 2: Check service permissions
:: ------------------------------------------------------------------
echo [2] Checking service permissions...
echo.

set "SERVICE_COUNT=0"
set "FIRST_SVC=1"
sc query type= service state= all | findstr "SERVICE_NAME:" > servicelist.tmp

if exist servicelist.tmp (
    for /f "tokens=2 delims=:" %%s in (servicelist.tmp) do (
        set "service=%%s"
        set "service=!service:~1!"
        
        sc sdshow "!service!" 2>nul | findstr /i "(WD|AU).*(GA|GW|WO|WD)" >nul
        if !errorlevel! equ 0 (
            echo [WARNING] Weak DACL on service: !service!
            set /a SERVICE_COUNT+=1
            
            :: Add to JSON
            if !FIRST_SVC! equ 1 (
                echo       {"service_name": "!service!", "issue": "weak_dacl"}" >> "%TEMP_FILE%"
                set "FIRST_SVC=0"
            ) else (
                echo       ,{"service_name": "!service!", "issue": "weak_dacl"}" >> "%TEMP_FILE%"
            )
        )
    )
    del servicelist.tmp
)

:: Close service array and start writable array
echo     ],
echo     "writable_issues": [
) >> "%TEMP_FILE%"

:: ------------------------------------------------------------------
:: PART 3: Check for writable system directories
:: ------------------------------------------------------------------
echo [3] Checking for writable system directories...
echo.

set "WRITABLE_COUNT=0"
set "FIRST_WRITE=1"

for %%d in (
    "C:\Windows"
    "C:\Windows\System32"
    "C:\Program Files"
    "C:\Program Files (x86)"
) do (
    echo Testing write access to: %%~d
    echo test > "%%~d\test_write.tmp" 2>nul
    if exist "%%~d\test_write.tmp" (
        echo [WARNING] Writable system directory: %%~d
        set /a WRITABLE_COUNT+=1
        del "%%~d\test_write.tmp" 2>nul
        
        :: Add to JSON
        if !FIRST_WRITE! equ 1 (
            echo       {"directory": "%%~d", "issue": "writable_system_dir"}" >> "%TEMP_FILE%"
            set "FIRST_WRITE=0"
        ) else (
            echo       ,{"directory": "%%~d", "issue": "writable_system_dir"}" >> "%TEMP_FILE%"
        )
    ) else (
        echo [OK] Not writable
    )
)

:: Close all arrays and add summary
(
echo     ]
echo   },
echo   "summary": {
echo     "filesystem_count": %WEAK_COUNT%,
echo     "service_count": %SERVICE_COUNT%,
echo     "writable_count": %WRITABLE_COUNT%,
set /a TOTAL_ISSUES=WEAK_COUNT + SERVICE_COUNT + WRITABLE_COUNT
echo     "total_issues": %TOTAL_ISSUES%
echo   }
echo }
) >> "%TEMP_FILE%"

:: ------------------------------------------------------------------
:: COPY TEMP FILE TO FINAL JSON
:: ------------------------------------------------------------------
copy "%TEMP_FILE%" "%JSON_FILE%" >nul

:: ------------------------------------------------------------------
:: SUMMARY
:: ------------------------------------------------------------------
echo.
echo ========================================
echo SCAN SUMMARY
echo ========================================
echo.
echo Filesystem weak permissions: %WEAK_COUNT%
echo Services with weak DACLs: %SERVICE_COUNT%
echo Writable system directories: %WRITABLE_COUNT%
echo.
echo Total issues found: %TOTAL_ISSUES%
echo.
echo Results saved to: %JSON_FILE%
echo.

:: Show JSON file contents
echo JSON File Contents:
echo -------------------
type "%JSON_FILE%"
echo.
pause
