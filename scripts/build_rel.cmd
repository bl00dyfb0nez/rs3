@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
cmake --build "C:\Users\Thewoodsman\rpcs3\build" --config Release --target rpcs3
echo BUILDEXIT=%ERRORLEVEL%
