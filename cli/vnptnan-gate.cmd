@echo off
rem Lệnh vnptnan-gate trên Windows: chạy bản bash qua Git Bash.
setlocal
set "ROOT=%~dp0.."
set "BASH=%ProgramFiles%\Git\bin\bash.exe"
if not exist "%BASH%" set "BASH=%LOCALAPPDATA%\Programs\Git\bin\bash.exe"
if not exist "%BASH%" ( echo Can Git for Windows. & exit /b 2 )
"%BASH%" "%ROOT%\cli\vnptnan-gate" %*
exit /b %ERRORLEVEL%
