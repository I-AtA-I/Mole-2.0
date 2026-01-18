@echo off

winget install python3 --accept-source-agreements --accept-package-agreements
python -m pip install pycryptodome
python -m pip install pywin32
python -m pip install pypiwin32
winget install Wireshark --accept-source-agreements --accept-package-agreements

python -m pip install colorama
python -m pip install pynput
python -m pip install opencv-python
python -m pip install numpy
python -m pip install sounddevice
python -m pip install soundfile
python -m pip install psutil
python -m pip install mss

python main.py

start cmd /k
exit
