Aion 2 game reader
==================
A small window that reads your own game's network traffic on your PC (passively, like
Not Meter) and sends it to the tracker page. Nothing is uploaded.

Needs: Windows, Npcap (https://npcap.com), administrator rights.
Works with ExitLag and other VPNs / game boosters.

Use it
  1. Run aion2_reader.exe (it asks for administrator rights).
  2. Start Aion 2 and log in. The dot turns green when it sees the game.
  3. Swap characters once; each one appears in the window and on the tracker page.

Build it yourself
  Double-click build_reader_exe.bat (needs Python 3 with "Add to PATH").
  It makes dist\aion2_reader.exe (the window) and dist\aion2_reader_tools.exe
  (console version for support: aion2_reader_tools.exe diag  /  capture).
