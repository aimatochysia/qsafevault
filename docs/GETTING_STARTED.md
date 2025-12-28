# Getting Started with QSafeVault

Welcome to QSafeVault! This guide will walk you through setting up and using the app for secure password management.

## Table of Contents
- [Installation](#installation)
- [First Launch](#first-launch)
- [Creating Your Vault](#creating-your-vault)
- [Adding Passwords](#adding-passwords)
- [Fast Unlock Setup](#fast-unlock-setup)
- [Syncing Devices](#syncing-devices)
- [Security Best Practices](#security-best-practices)
- [Troubleshooting](#troubleshooting)

## Installation

### Windows
1. Download the latest `.exe` installer from [Releases](https://github.com/aimatochysia/qsafevault/releases)
2. Run the installer and follow the prompts
3. Launch QSafeVault from the Start Menu

### Linux
```bash
# Option 1: Download .deb package (Debian/Ubuntu)
sudo dpkg -i qsafevault_*.deb

# Option 2: Build from source
git clone https://github.com/aimatochysia/qsafevault.git
cd qsafevault
flutter build linux --release
```

### Android
1. Download the APK from [Releases](https://github.com/aimatochysia/qsafevault/releases)
2. Enable "Install from unknown sources" in Settings
3. Open the APK and tap Install
4. Or install from source:
```bash
flutter build apk --release
adb install build/app/outputs/apk/release/app-release.apk
```

### macOS (Development)
```bash
git clone https://github.com/aimatochysia/qsafevault.git
cd qsafevault
flutter build macos --release
```

### iOS (Development)
```bash
git clone https://github.com/aimatochysia/qsafevault.git
cd qsafevault
flutter build ios --release
# Open ios/Runner.xcworkspace in Xcode to deploy
```

## First Launch

When you first open QSafeVault, you'll see the vault creation screen.

### Step 1: Create Your Master Password

Your master password is the key to your vault. Choose wisely:

**Requirements:**
- Minimum 8 characters (16+ recommended)
- Mix of uppercase, lowercase, numbers, and symbols
- Something you can remember but others can't guess

**Tips:**
- Use a passphrase: "correct-horse-battery-staple-42!"
- Avoid personal information (birthdays, names)
- Don't reuse passwords from other services

### Step 2: Confirm Your Password

Re-enter your master password to confirm. This ensures you didn't make a typo.

### Step 3: Vault Created!

Your vault is now created and encrypted with AES-256-GCM. The encryption key is derived from your master password using Argon2id, which takes a few seconds to compute (this is intentional for security).

## Creating Your Vault

### Vault Storage Location

Your encrypted vault is stored locally on your device:

| Platform | Location |
|----------|----------|
| Windows | `%APPDATA%\QSafeVault\vault.qsv` |
| Linux | `~/.local/share/qsafevault/vault.qsv` |
| macOS | `~/Library/Application Support/QSafeVault/vault.qsv` |
| Android | App private storage (sandboxed) |
| iOS | App private storage (sandboxed) |

### Backup Your Vault

It's important to backup your encrypted vault file:

1. Go to **Settings** → **Backup**
2. Choose a backup location (USB drive, cloud storage, etc.)
3. The backup is fully encrypted - safe to store anywhere
4. Keep multiple backups in different locations

## Adding Passwords

### Manual Entry

1. Tap the **+** button or **Add Entry**
2. Fill in the fields:
   - **Name**: Description (e.g., "Gmail")
   - **Username**: Your login username/email
   - **Password**: Your password (or generate one)
   - **URL**: Website address (optional)
   - **Notes**: Additional information (optional)
3. Tap **Save**

### Password Generator

QSafeVault includes a secure password generator:

1. When adding/editing an entry, tap the **Generate** button
2. Configure options:
   - Length (16-64 characters recommended)
   - Include uppercase (A-Z)
   - Include lowercase (a-z)
   - Include numbers (0-9)
   - Include symbols (!@#$%^&*)
3. Tap **Use Password**

### Organizing Entries

- **Search**: Use the search bar to find entries quickly
- **Categories**: Group entries by category (coming soon)
- **Favorites**: Star important entries for quick access

## Fast Unlock Setup

Fast Unlock lets you re-open your vault quickly without typing your full master password.

### How It Works

1. A wrapped key is stored in platform secure storage (TPM/Secure Enclave)
2. Biometric authentication (fingerprint/face) unwraps the key
3. The unwrapped key decrypts your vault

### Setup Steps

1. Unlock your vault with your master password
2. Go to **Settings** → **Security**
3. Enable **Fast Unlock**
4. Choose your method:
   - **Biometric** (fingerprint/face) - Most secure
   - **PIN** (4-6 digits) - Good balance
   - **Device Password** - Uses system lock screen
5. Authenticate to confirm

### Platforms Supported

| Platform | Biometric | PIN | Device Password |
|----------|-----------|-----|-----------------|
| Windows | Windows Hello | ✓ | ✓ |
| Linux | - | ✓ | - |
| macOS | Touch ID | ✓ | ✓ |
| Android | Fingerprint/Face | ✓ | ✓ |
| iOS | Face ID/Touch ID | ✓ | ✓ |

## Syncing Devices

QSafeVault uses peer-to-peer sync with end-to-end encryption. Your passwords never touch any server in plaintext.

### Quick Sync Guide

**On Device A (Sender):**
1. Open vault and go to **Sync**
2. Tap **Send**
3. Enter a transfer password (min 6 characters)
4. An 8-character invite code appears (e.g., `Ab3Xy9Zk`)
5. Share the code and password with Device B

**On Device B (Receiver):**
1. Open vault and go to **Sync**
2. Tap **Receive**
3. Enter the 8-character invite code (case-sensitive!)
4. Enter the transfer password
5. Wait for transfer to complete

### Sync Methods

1. **WebRTC (P2P)** - Direct device-to-device, fastest
2. **Relay (Fallback)** - Via encrypted relay server if P2P fails

### Security

- End-to-end encrypted with key derived from invite code + password
- Server never sees plaintext
- Transfer password never stored
- Invite codes expire in 30 seconds

For detailed sync documentation, see [SYNC_GUIDE.md](../SYNC_GUIDE.md).

## Security Best Practices

### Password Hygiene

1. **Use unique passwords** for every account
2. **Use generated passwords** (20+ characters)
3. **Rotate passwords** periodically for critical accounts
4. **Never share** your master password

### Vault Security

1. **Strong master password** - 16+ characters, complex
2. **Enable fast unlock** - But never skip master password checks
3. **Lock when away** - Auto-lock after 5 minutes idle
4. **Regular backups** - Encrypted backups to separate location

### Device Security

1. **Keep software updated** - OS and app updates
2. **Don't root/jailbreak** - Reduces security guarantees
3. **Use screen lock** - PIN, pattern, or biometric
4. **Enable full disk encryption** - Already default on most devices

### Sync Security

1. **Verify peers** - Check device fingerprints
2. **Use strong transfer passwords** - Not related to master password
3. **New codes per sync** - Don't reuse invite codes
4. **Sync over trusted networks** - Avoid public WiFi

## Troubleshooting

### "Incorrect Password"

- Check Caps Lock
- Try typing slowly
- Remember: master password is case-sensitive
- If truly forgotten, you must restore from backup

### "Vault Corrupted"

1. Don't panic - this usually means integrity check failed
2. Try restarting the app
3. If persistent, restore from your latest backup
4. Contact support if issue continues

### Sync Problems

**"Invite code not found"**
- Code is case-sensitive (Ab3X ≠ ab3x)
- Codes expire in 30 seconds
- Sender must keep sync screen open

**"Transfer password mismatch"**
- Passwords must match exactly
- No trailing spaces
- Try typing both again

**"P2P connection failed"**
- App will automatically try relay fallback
- Check both devices have internet
- Disable VPN temporarily

### Fast Unlock Not Working

1. Re-enroll biometric in device settings
2. Disable and re-enable Fast Unlock in app
3. Check that biometric hardware is functioning
4. On Android: Clear app data and set up again

### Performance Issues

- Large vaults (1000+ entries) may be slower
- Keep devices charged during sync
- Close other apps to free memory
- Consider splitting into multiple vaults

## Next Steps

- [Crypto Engine Documentation](CRYPTO_ENGINE.md) - Technical details
- [Security Architecture](SECURITY_ARCHITECTURE.md) - How security works
- [SoftHSM Installation](SOFTHSM_INSTALLATION.md) - Advanced HSM setup
- [Sync Guide](../SYNC_GUIDE.md) - Detailed sync documentation

## Getting Help

- **Issues**: [GitHub Issues](https://github.com/aimatochysia/qsafevault/issues)
- **Security**: Report security issues privately via email
- **Documentation**: Check the `docs/` directory

---

Welcome to secure password management with QSafeVault! 🔐
