@echo off
python -m pip install --upgrade pip
python -m pip install scapy psutil pyinstaller
python -m PyInstaller --onefile --uac-admin --hidden-import psutil --collect-all scapy --name aion2_reader aion2_reader.py
echo.
echo Done. The program is in the dist folder: dist\aion2_reader.exe
pause
