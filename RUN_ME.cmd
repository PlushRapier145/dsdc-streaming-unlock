@echo off
setlocal EnableDelayedExpansion
title DSDC Streaming Memory Unlock

rem ======================================================================
rem  Double-click this file to run the patcher.
rem
rem  All it does is find a Python 3.8 or newer on this machine and run
rem  dsdc_streaming_unlock.py, which sits next to this file. It writes
rem  nothing, changes no settings, needs no administrator, and touches
rem  neither the registry nor the network. It cannot patch anything on its
rem  own: it only ever passes --interactive, so the game is modified only
rem  after you pick it from a menu and confirm.
rem
rem  This whole file is reprinted in README.md. Compare them if you like.
rem
rem  PlushRapier145, MIT licence.
rem ======================================================================

set "SCRIPT=%~dp0dsdc_streaming_unlock.py"

if not exist "%SCRIPT%" (
    echo.
    echo   I cannot find dsdc_streaming_unlock.py next to this file.
    echo.
    echo   If you started this from inside the ZIP, Windows only unpacked
    echo   this one file. Close this window, right-click the ZIP, choose
    echo   "Extract All...", and run RUN_ME.cmd from the folder it makes.
    echo.
    pause
    goto :eof
)

rem --- 1) The official "py" launcher. It is never the Microsoft Store stub.
py -3 -c "import sys;sys.exit(0 if sys.version_info>=(3,8) else 1)" >nul 2>&1
if not errorlevel 1 (
    py -3 "%SCRIPT%" --interactive %*
    goto :done
)

rem --- 2) python on PATH.
rem     Skip the 0-byte alias in WindowsApps: on a machine without Python
rem     that one opens the Microsoft Store instead of running anything.
rem     The test is plain string substitution on purpose. "find" and
rem     "findstr" can resolve to the Git Bash or GnuWin32 builds on a
rem     modder's PATH, which take different arguments and fail oddly.
for /f "delims=" %%I in ('where python 2^>nul') do (
    set "CAND=%%I"
    if "!CAND:WindowsApps=!"=="!CAND!" (
        "!CAND!" -c "import sys;sys.exit(0 if sys.version_info>=(3,8) else 1)" >nul 2>&1
        if not errorlevel 1 (
            "!CAND!" "%SCRIPT%" --interactive %*
            goto :done
        )
    )
)

echo.
echo   Python is not installed here, or the one that is, is older than 3.8.
echo.
echo   Get it from   https://www.python.org/downloads/
echo   In the installer, tick "Add python.exe to PATH".
echo   Then double-click this file again.
echo.

:done
echo.
pause
