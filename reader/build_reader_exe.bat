@echo off
python -m pip install --upgrade pip
python -m pip install scapy psutil pyinstaller
rem The app (a window, no console):
python -m PyInstaller --onefile --windowed --uac-admin --hidden-import psutil --collect-all scapy --name aion2_reader aion2_reader.py
rem The same program with a console, for diag / capture commands:
python -m PyInstaller --onefile --uac-admin --hidden-import psutil --collect-all scapy --name aion2_reader_tools aion2_reader.py
echo.
echo Done. The programs are in the dist folder:
echo   dist\aion2_reader.exe        (the app)
echo   dist\aion2_reader_tools.exe  (console version: aion2_reader_tools.exe diag / capture)
pause
