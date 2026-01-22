:: fill-to-last-byte.bat - Fills until 0 bytes free
@echo off
setlocal enabledelayedexpansion

echo DISK FILLER - FILL TO LAST BYTE
echo ===============================
echo.

set /p "d=Drive letter to DESTROY: "
set "d=!d:~0,1!"
set "dpath=!d!:\"

if not exist "!dpath!" (
    echo Drive !dpath! not found!
    pause
    exit /b 1
)

echo Testing write...
echo X > "!dpath!test.tmp" 2>nul && del "!dpath!test.tmp" 2>nul || (
    echo Cannot write! Run as Admin.
    pause
    exit /b 1
)

echo.
echo [!!!] WARNING: WILL FILL DRIVE !dpath! COMPLETELY!
echo [!!!] SYSTEM WILL CRASH WHEN DISK IS FULL!
echo [!!!] PRESS CTRL+C NOW TO CANCEL!
echo.
timeout /t 3 /nobreak >nul

set "dir=!dpath!FILL_MAX_!RANDOM!!RANDOM!"
mkdir "!dir!" 2>nul
if not exist "!dir!" (
    echo Cannot create directory!
    pause
    exit /b 1
)

set "cnt=0"
set "FSUTIL=C:\Windows\System32\fsutil.exe"

echo Starting to fill !dpath!...
echo Working directory: !dir!
echo.

:: Phase 1: Fill with huge files
echo PHASE 1: Creating huge files...
:phase1
set /a cnt+=1

:: Try decreasing sizes until one works
for %%s in (10737418240 5368709120 2147483648 1073741824 536870912 268435456 134217728 67108864) do (
    set "fname=file!cnt!_%%s.dat"
    echo [!cnt!] Trying %%s bytes...
    
    "%FSUTIL%" file createnew "!dir!\!fname!" %%s >nul 2>&1
    if !errorlevel! equ 0 (
        echo Created: !fname!
        goto :phase1
    )
)

:: If we get here, even 64MB files fail
echo [!] Even 64MB files failing. Moving to Phase 2...
goto :phase2

:: Phase 2: Fill with smaller files
:phase2
echo.
echo PHASE 2: Creating smaller files...
:phase2_loop
set /a cnt+=1

for %%s in (33554432 16777216 8388608 4194304 2097152 1048576) do (
    set "fname=small!cnt!_%%s.dat"
    echo [!cnt!] Trying %%s bytes...
    
    "%FSUTIL%" file createnew "!dir!\!fname!" %%s >nul 2>&1
    if !errorlevel! equ 0 (
        echo Created: !fname!
        goto :phase2_loop
    )
)

:: Phase 3: Fill with tiny files
:phase3
echo.
echo PHASE 3: Creating tiny files...
:phase3_loop
set /a cnt+=1

for %%s in (524288 262144 131072 65536 32768 16384 8192 4096 2048 1024 512 256 128 64 32 16 8 4 2 1) do (
    set "fname=tiny!cnt!_%%s.dat"
    
    "%FSUTIL%" file createnew "!dir!\!fname!" %%s >nul 2>&1
    if !errorlevel! equ 0 (
        echo [!cnt!] Created: !fname! (%%s bytes)
        goto :phase3_loop
    )
)

:: Phase 4: Try to write single bytes
:phase4
echo.
echo PHASE 4: Writing single bytes...
set /a cnt+=1
set "fname=byte!cnt!.dat"

echo [!cnt!] Trying to write 1 byte...
echo X > "!dir!\!fname!" 2>nul
if exist "!dir!\!fname!" (
    echo Created: !fname! (1 byte)
    goto :phase4
)

:: Final: Drive is FULL
echo.
echo ========================================
echo DRIVE !dpath! IS COMPLETELY FULL!
echo ========================================
echo Created !cnt! files
echo Directory: !dir!
echo.

:: Try to create one more file to confirm
echo test > "!dpath!full_test.tmp" 2>nul
if exist "!dpath!full_test.tmp" (
    del "!dpath!full_test.tmp" 2>nul
    echo [!] WARNING: Drive still has some space!
    echo Press any key to continue filling...
    pause
    goto :phase1
) else (
    echo [✓] CONFIRMED: Drive has 0 bytes free!
)

echo.
set /p "del=Delete files to restore space? (y/N): "
if /i "!del!"=="y" (
    echo Deleting...
    timeout /t 2 >nul
    rmdir /s /q "!dir!" 2>nul
    if exist "!dir!" (
        echo Could not delete all files.
        echo Manual cleanup: !dir!
    ) else (
        echo Files deleted. Space restored.
    )
) else (
    echo Files preserved at: !dir!
    echo You have 0 bytes free on !dpath!
)

echo.
pause
