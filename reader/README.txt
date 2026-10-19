Aion 2 game reader
==================
Reads your own game's network traffic on your PC (passively, like Not Meter) and
serves it to the tracker page at http://127.0.0.1:17520/state. Nothing is uploaded.

Needs: Windows, Npcap (https://npcap.com), run as administrator, ExitLag/VPN off.

Easiest: build the exe
  1. Install Python 3 and tick "Add to PATH".
  2. Double-click build_reader_exe.bat (it installs scapy, psutil and PyInstaller).
  3. Run dist\aion2_reader.exe as administrator and keep the window open.

Or run directly:  python aion2_reader.py  (as administrator)
