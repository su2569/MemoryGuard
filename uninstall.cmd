@echo off
rem Stop and remove the MemoryGuard service. Config/log under ProgramData are kept.
setlocal
sc stop MemoryGuard >nul 2>&1
sc delete MemoryGuard
echo removed. config/log kept at C:\ProgramData\MemoryGuard
endlocal
