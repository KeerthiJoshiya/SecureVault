@echo off
setlocal
call "%~dp0build.cmd"
if errorlevel 1 exit /b 1
pushd "%~dp0"
javaw -cp out securevault.Main
set "run_result=%errorlevel%"
popd
exit /b %run_result%
