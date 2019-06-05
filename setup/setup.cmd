@echo off
set dirpath=%~dp0
setlocal
set key="HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Microsoft SDKs\Windows\v10.0"
set value=ProductVersion
set newdata=10.0.17763

for /f "tokens=2* skip=2" %%a in ('reg query %key% /v %value%') do (
    set type=%%a
    set data=%%b
)
echo %data% >> "%dirpath%\installlog.txt"
echo %data% | find /i "%newdata%" > nul
if %errorlevel% neq 0 (
    echo The product version of Windows SDK must be at least 10.0.17763 >> "%dirpath%\installlog.txt"
    exit
)

set key="HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows Kits\Installed Roots"
set value=WindowsDebuggersRoot10
set newdata=echo

for /f "tokens=2* skip=2" %%a in ('reg query %key% /v %value%') do (
    set type=%%a
    set data=%%b
)
echo %data% | find /i "%newdata%" > nul
if %errorlevel% equ 0 (
    echo This script requires Windows Debugging tools to be installed >> "%dirpath%\installlog.txt"
    exit
)

echo prerequisites found, continuing installation >> "%dirpath%\installlog.txt"

copy "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\symchk.exe" "%~dp0.\tools\x64"
echo staged symchk.exe in tools\x64 >> "%dirpath%\installlog.txt"
copy "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\SymbolCheck.dll" "%~dp0.\tools\x64"
echo staged SymbolCheck.dll in tools\x64 >> "%dirpath%\installlog.txt"
copy "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\symsrv.dll" "C:\Windows\System32"
echo staged symsrv.dll in Windows\System32 >> "%dirpath%\installlog.txt"
copy "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\symsrv.yes" "C:\Windows\System32"
echo staged symsrv.yes in Windows\System32 >> "%dirpath%\installlog.txt"