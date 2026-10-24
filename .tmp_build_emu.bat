@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d C:\Users\Thewoodsman\rpcs3
cmake --build build --config Release --target rpcs3
exit /b %ERRORLEVEL%
