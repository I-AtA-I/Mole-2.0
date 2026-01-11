@echo off

winget install python3 --accept-source-agreements --accept-package-agreements
python main.py
python -m pip install pycryptodome
python -m pip install pywin32
python -m pip install pypiwin32
winget install Wireshark --accept-source-agreements --accept-package-agreements


start cmd /k
exit
