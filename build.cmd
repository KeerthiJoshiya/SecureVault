@echo off
setlocal
pushd "%~dp0"
where javac >nul 2>nul
if errorlevel 1 (
    echo JDK 21 or newer is required. Install a JDK and add its bin folder to PATH.
    popd
    exit /b 1
)
if not exist "out" mkdir "out"
if "%~1"=="test" (
    powershell -NoProfile -Command "$sources = (Get-ChildItem src,tests -Recurse -Filter *.java).FullName; javac --release 21 -encoding UTF-8 -d out $sources; exit $LASTEXITCODE"
) else (
    powershell -NoProfile -Command "$sources = (Get-ChildItem src -Recurse -Filter *.java).FullName; javac --release 21 -encoding UTF-8 -d out $sources; exit $LASTEXITCODE"
)
set "build_result=%errorlevel%"
popd
exit /b %build_result%
