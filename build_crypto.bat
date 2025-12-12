@echo off
REM Build script for QSafeVault Crypto Engine (Windows)
REM Builds the Rust library for Windows

setlocal

set SCRIPT_DIR=%~dp0
set CRYPTO_ENGINE_DIR=%SCRIPT_DIR%crypto_engine

echo Building QSafeVault Crypto Engine...

REM Change to crypto_engine directory
cd /d "%CRYPTO_ENGINE_DIR%"

REM Determine build mode
set BUILD_MODE=%1
if "%BUILD_MODE%"=="" set BUILD_MODE=debug

if "%BUILD_MODE%"=="release" (
    echo Building in release mode...
    cargo build --release
    set BUILD_DIR=target\release
) else (
    echo Building in debug mode...
    cargo build
    set BUILD_DIR=target\debug
)

set LIB_NAME=crypto_engine.dll

echo Built %LIB_NAME% for Windows
echo Location: %CRYPTO_ENGINE_DIR%\%BUILD_DIR%\%LIB_NAME%

echo Build complete!

endlocal
