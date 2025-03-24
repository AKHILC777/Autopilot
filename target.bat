@echo off
:: Quick Windows 11 23H2 Update Blocker
:: Blocks major version upgrades only
 
:: Check admin rights
NET FILE 1>NUL 2>NUL || (
    PowerShell -Command "Start-Process -Verb RunAs -FilePath 'cmd' -ArgumentList '/c \"%~0\"'"
    exit
)
 
echo Blocking major version updates...
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "TargetReleaseVersion" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "TargetReleaseVersionInfo" /t REG_SZ /d "23H2" /f
 
echo Done! Windows will:
echo - Still get security updates
echo - Block 24H2/any major version upgrade
echo.
echo To undo:
echo 1. Run 'regedit'
echo 2. Delete these keys:
echo    HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate
echo.
pause