#!/bin/bash
# Build Rust crypto library for Android
# This script builds the Rust library for Android and places it in the correct location

set -e

echo "Building Rust crypto library for Android..."

# Change to crypto_engine directory
cd "$(dirname "$0")/crypto_engine"

# Check if cargo is installed
if ! command -v cargo &> /dev/null; then
    echo "Error: cargo not found. Please install Rust from https://rustup.rs/"
    exit 1
fi

# Check if Android NDK is set up
if [ -z "$ANDROID_NDK_HOME" ] && [ -z "$NDK_HOME" ]; then
    echo "Warning: ANDROID_NDK_HOME or NDK_HOME not set."
    echo "You may need to set this to build for Android."
    echo "Example: export ANDROID_NDK_HOME=/path/to/android/sdk/ndk/<version>"
fi

# Android targets
TARGETS=(
    "aarch64-linux-android"    # arm64-v8a
    "armv7-linux-androideabi"  # armeabi-v7a
    "x86_64-linux-android"     # x86_64
    "i686-linux-android"       # x86
)

# Install targets if not already installed
for target in "${TARGETS[@]}"; do
    echo "Checking target: $target"
    rustup target add "$target" || true
done

# Build for each target
for target in "${TARGETS[@]}"; do
    echo "Building for $target..."
    cargo build --release --target "$target"
    
    # Map Rust target to Android ABI
    case "$target" in
        "aarch64-linux-android")
            abi="arm64-v8a"
            ;;
        "armv7-linux-androideabi")
            abi="armeabi-v7a"
            ;;
        "x86_64-linux-android")
            abi="x86_64"
            ;;
        "i686-linux-android")
            abi="x86"
            ;;
    esac
    
    # Create jniLibs directory structure
    jni_dir="../android/app/src/main/jniLibs/$abi"
    mkdir -p "$jni_dir"
    
    # Copy the library
    echo "Copying library to $jni_dir/libcrypto_engine.so"
    cp "target/$target/release/libcrypto_engine.so" "$jni_dir/libcrypto_engine.so"
done

echo ""
echo "✓ Android Rust crypto library built successfully!"
echo ""
echo "Libraries placed in:"
for target in "${TARGETS[@]}"; do
    case "$target" in
        "aarch64-linux-android")
            abi="arm64-v8a"
            ;;
        "armv7-linux-androideabi")
            abi="armeabi-v7a"
            ;;
        "x86_64-linux-android")
            abi="x86_64"
            ;;
        "i686-linux-android")
            abi="x86"
            ;;
    esac
    echo "  android/app/src/main/jniLibs/$abi/libcrypto_engine.so"
done
echo ""
echo "You can now build your Flutter app for Android."
