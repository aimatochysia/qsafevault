#!/bin/bash
# Build Rust crypto library for iOS
# This script builds the Rust library for iOS and creates an XCFramework

set -e

echo "Building Rust crypto library for iOS..."

# Change to crypto_engine directory
cd "$(dirname "$0")/crypto_engine"

# Check if cargo is installed
if ! command -v cargo &> /dev/null; then
    echo "Error: cargo not found. Please install Rust from https://rustup.rs/"
    exit 1
fi

# Check if we're on macOS
if [ "$(uname)" != "Darwin" ]; then
    echo "Error: iOS builds must be run on macOS"
    exit 1
fi

# iOS targets
TARGETS=(
    "aarch64-apple-ios"           # iOS devices (ARM64)
    "aarch64-apple-ios-sim"       # iOS simulator on Apple Silicon
    "x86_64-apple-ios"            # iOS simulator on Intel
)

# Install targets if not already installed
for target in "${TARGETS[@]}"; do
    echo "Checking target: $target"
    rustup target add "$target" || true
done

# Create output directory
OUTPUT_DIR="target/ios-universal"
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

# Build for each target
for target in "${TARGETS[@]}"; do
    echo "Building for $target..."
    cargo build --release --target "$target"
done

# Create fat binary for simulator (x86_64 + aarch64-sim)
echo "Creating universal simulator library..."
mkdir -p "$OUTPUT_DIR/simulator"
lipo -create \
    "target/x86_64-apple-ios/release/libcrypto_engine.a" \
    "target/aarch64-apple-ios-sim/release/libcrypto_engine.a" \
    -output "$OUTPUT_DIR/simulator/libcrypto_engine.a"

# Copy device library
echo "Copying device library..."
mkdir -p "$OUTPUT_DIR/device"
cp "target/aarch64-apple-ios/release/libcrypto_engine.a" "$OUTPUT_DIR/device/libcrypto_engine.a"

# Create XCFramework
echo "Creating XCFramework..."
XCFRAMEWORK_DIR="../ios/Frameworks/CryptoEngine.xcframework"
rm -rf "$XCFRAMEWORK_DIR"

xcodebuild -create-xcframework \
    -library "$OUTPUT_DIR/device/libcrypto_engine.a" \
    -library "$OUTPUT_DIR/simulator/libcrypto_engine.a" \
    -output "$XCFRAMEWORK_DIR"

echo ""
echo "✓ iOS Rust crypto library built successfully!"
echo ""
echo "XCFramework created at:"
echo "  ios/Frameworks/CryptoEngine.xcframework"
echo ""
echo "You can now build your Flutter app for iOS."
echo ""
echo "Note: You may need to link this framework in Xcode:"
echo "  1. Open ios/Runner.xcworkspace in Xcode"
echo "  2. Select Runner target"
echo "  3. Go to 'Frameworks, Libraries, and Embedded Content'"
echo "  4. Add CryptoEngine.xcframework"
echo "  5. Set it to 'Embed & Sign'"
