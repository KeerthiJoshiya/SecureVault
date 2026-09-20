@echo off
setlocal
call "%~dp0build.cmd" test
if errorlevel 1 exit /b 1
pushd "%~dp0"
java -cp out securevault.TestRunner
set "test_result=%errorlevel%"
popd
exit /b %test_result%
