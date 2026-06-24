@echo off
rem SPDX-License-Identifier: LGPL-3.0-or-later
setlocal EnableExtensions

net session >nul 2>&1
if not "%errorlevel%"=="0" (
	echo Administrator rights are required to install FileXRay.
	echo Run this script from an elevated Command Prompt.
	exit /b 5
)

set "DLL_PATH=%~dp0FileXRay.dll"

if not exist "%DLL_PATH%" (
	echo FileXRay DLL was not found:
	echo   %DLL_PATH%
	exit /b 1
)

echo Registering FileXRay property sheet handler...
echo   DLL: %DLL_PATH%
regsvr32.exe /s "%DLL_PATH%"
if errorlevel 1 (
	echo Registration failed. regsvr32 exit code: %errorlevel%
	exit /b %errorlevel%
)

echo FileXRay installed.
echo Reopen file Properties windows to load the new property sheet.
exit /b 0
