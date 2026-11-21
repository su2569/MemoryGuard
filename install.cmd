@echo off
rem Install / upgrade MemoryGuard as a Windows service. Must run elevated.
setlocal
set "SRC=%~dp0MemoryGuardService.exe"
set "DIR=C:\ProgramData\MemoryGuard"
set "DST=%DIR%\MemoryGuardService.exe"

if not exist "%SRC%" (
  echo missing build: %SRC%
  echo build it first: g++ MemoryGuardService.cpp -o MemoryGuardService.exe -std=c++17 -O2 -municode -g3 -lwtsapi32 -ladvapi32 -luser32 -lpsapi -lwintrust -lcrypt32
  exit /b 1
)
if not exist "%DIR%" mkdir "%DIR%"

sc query MemoryGuard >nul 2>&1
if errorlevel 1 (
  copy /y "%SRC%" "%DST%" >nul || exit /b 1
  sc create MemoryGuard binPath= "%DST%" start= auto DisplayName= "MemoryGuard 内存守护"
  sc description MemoryGuard "Windows 内存守护服务：温和回收 + OOM killer（Linux 复刻版）"
) else (
  sc stop MemoryGuard >nul 2>&1
  copy /y "%SRC%" "%DST%" >nul || exit /b 1
)

sc start MemoryGuard
sc query MemoryGuard
echo.
echo config: %DIR%\guard.ini   log: %DIR%\guard.log
endlocal
