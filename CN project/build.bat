@echo off
echo =======================================================================
echo     Compiling Data Link Layer Protocol Engine (MinGW C++)
echo =======================================================================

g++ -std=c++14 -O2 src/main.cpp src/hamming.cpp src/csma_cd.cpp src/go_back_n.cpp src/udp_socket.cpp src/node.cpp -o dll_sim.exe -lws2_32

if %ERRORLEVEL% equ 0 (
    echo.
    echo [SUCCESS] Compilation successful! Executable generated: dll_sim.exe
) else (
    echo.
    echo [ERROR] Compilation failed. Please check your MinGW g++ installation.
)
