@echo off
echo ================================
echo      MOLE - INSTALLER
echo ================================
echo.

:: 1. CHECK/INSTALL PYTHON (SILENT)
echo [1] Checking Python...
where python >nul 2>nul
if errorlevel 1 (
    echo   Installing Python...
    winget install Python.Python.3.11 --silent --accept-package-agreements >nul 2>&1
)

:: 2. UPGRADE PIP (CRITICAL FOR SPEED)
echo [2] Upgrading pip...
python -m pip install --upgrade pip --quiet >nul 2>&1

:: 3. INSTALL ALL PACKAGES AT ONCE (THIS IS THE FAST PART)
echo [3] Installing ALL packages in one command...
echo    This is faster than installing one by one...
python -m pip install colorama pywin32 pycryptodome pynput opencv-python numpy sounddevice soundfile psutil mss pillow readline pyreadline3 --quiet --disable-pip-version-check

:: 4. INSTALL WIRESHARK (SILENT)
echo [4] Installing Wireshark (optional)...
where dumpcap >nul 2>nul
if errorlevel 1 (
    winget install WiresharkFoundation.Wireshark --silent --accept-package-agreements >nul 2>&1
    echo   Wireshark installed
) else (
    echo   Wireshark already installed
)

:: 5. QUICK VERIFICATION
echo [5] Verifying installs...
python -c "
try:
    import colorama, win32crypt, pynput, cv2
    from Crypto.Cipher import AES
    print('  SUCCESS: Core packages installed')
except ImportError as e:
    print('  WARNING: Missing:', str(e))
"

:: 6. LAUNCH
echo.
echo ================================
echo        READY TO USE
echo ================================
echo.
timeout /t 2 >nul
python main.py

pause
