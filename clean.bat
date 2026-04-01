@echo off
setlocal EnableExtensions EnableDelayedExpansion

REM ===============================
REM Self-elevation check
REM ===============================
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -NoProfile -ExecutionPolicy Bypass -Command ^
        "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

REM ===============================
REM Kill Python & mitmproxy processes
REM ===============================
taskkill /F /IM python.exe   /T >nul 2>&1
taskkill /F /IM pythonw.exe  /T >nul 2>&1
taskkill /F /IM mitmdump.exe /T >nul 2>&1
taskkill /F /IM mitmproxy.exe    >nul 2>&1
taskkill /F /IM mitmweb.exe      >nul 2>&1

REM ===============================
REM Remove WinINET proxy settings
REM ===============================
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable   /f >nul 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer   /f >nul 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyOverride /f >nul 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v AutoConfigURL /f >nul 2>&1

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" ^
    /v ProxyEnable /t REG_DWORD /d 0 /f >nul 2>&1

REM ===============================
REM Reset WinHTTP proxy (system-wide)
REM ===============================
netsh winhttp reset proxy >nul 2>&1

REM ===============================
REM Clear proxy environment variables
REM ===============================
setx HTTP_PROXY ""  >nul 2>&1
setx HTTPS_PROXY "" >nul 2>&1
setx ALL_PROXY ""   >nul 2>&1
setx http_proxy ""  >nul 2>&1
setx https_proxy "" >nul 2>&1
setx all_proxy ""   >nul 2>&1

REM ===============================
REM Flush DNS
REM ===============================
ipconfig /flushdns >nul 2>&1

REM ===============================
REM Final (ONLY output)
REM ===============================
echo Finished.
pause