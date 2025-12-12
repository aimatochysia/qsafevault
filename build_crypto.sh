#!/bin/bash
# Build script for QSafeVault Crypto Engine
# Builds the Rust library for the current platform

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
CRYPTO_ENGINE_DIR="$SCRIPT_DIR/crypto_engine"

echo "Building QSafeVault Crypto Engine..."

# Change to crypto_engine directory
cd "$CRYPTO_ENGINE_DIR"

# Determine build mode
BUILD_MODE="${1:-debug}"

if [ "$BUILD_MODE" = "release" ]; then
    echo "Building in release mode..."
    cargo build --release
    BUILD_DIR="target/release"
else
    echo "Building in debug mode..."
    cargo build
    BUILD_DIR="target/debug"
fi

# Determine platform and library extension
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    LIB_NAME="libcrypto_engine.so"
    PLATFORM="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    LIB_NAME="libcrypto_engine.dylib"
    PLATFORM="macos"
elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
    LIB_NAME="crypto_engine.dll"
    PLATFORM="windows"
else
    echo "Unsupported platform: $OSTYPE"
    exit 1
fi

echo "Built $LIB_NAME for $PLATFORM"
echo "Location: $CRYPTO_ENGINE_DIR/$BUILD_DIR/$LIB_NAME"

# Optional: Copy to a common location for Flutter to find
# Uncomment if you want to copy the library to a specific location
# OUTPUT_DIR="$SCRIPT_DIR/lib/native"
# mkdir -p "$OUTPUT_DIR/$PLATFORM"
# cp "$CRYPTO_ENGINE_DIR/$BUILD_DIR/$LIB_NAME" "$OUTPUT_DIR/$PLATFORM/"
# echo "Copied to $OUTPUT_DIR/$PLATFORM/$LIB_NAME"

echo "Build complete!"
