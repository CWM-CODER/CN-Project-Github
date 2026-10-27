@echo off
echo =======================================================================
echo     DATA LINK LAYER FULL PROTOCOL SUITE & PYSHARK SNIFFER
echo =======================================================================
echo.

echo [1/3] Building C++ Simulation...
call build.bat
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%

echo.
echo [2/3] Running Data Link Layer Simulation (C++ Engine)...
.\dll_sim.exe quick

echo.
echo [3/3] Running PyShark Protocol Dissector on Generated Loopback Capture...
python sniffer/pyshark_sniffer.py capture.pcap

echo.
echo =======================================================================
echo     All Systems Executed & Verified Successfully!
echo =======================================================================
pause
