@echo off
rem SPDX-License-Identifier: LGPL-3.0-or-later
setlocal EnableExtensions

net session >nul 2>&1
if not "%errorlevel%"=="0" (
	echo Administrator rights are required to uninstall FileXRay.
	echo Run this script from an elevated Command Prompt.
	exit /b 5
)

set "DLL_PATH=%~dp0FileXRay.dll"

if not exist "%DLL_PATH%" (
	echo FileXRay DLL was not found:
	echo   %DLL_PATH%
	echo The DLL is needed because COM unregister is implemented by DllUnregisterServer.
	exit /b 1
)

echo Unregistering FileXRay property sheet handler...
echo   DLL: %DLL_PATH%
regsvr32.exe /s /u "%DLL_PATH%"
if errorlevel 1 (
	echo Unregistration failed. regsvr32 exit code: %errorlevel%
	exit /b %errorlevel%
)

echo FileXRay uninstalled.
echo Reopen file Properties windows to unload the property sheet.
exit /b 0
