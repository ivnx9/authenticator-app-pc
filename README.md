# 🔐 Authenticator

A simple, desktop-based authenticator app for Windows that helps you manage your Two-Factor Authentication (2FA) accounts in one place.

Import authenticator accounts using QR codes, generate time-based one-time passwords (TOTP), and protect your saved accounts with password-based encryption.

## ✨ Features

- **🔑 TOTP Code Generation** — Generate time-based one-time passwords for supported 2FA services.
- **📷 QR Code Import** — Import multiple authenticator accounts from supported QR codes, including compatible authenticator migration QR codes.
- **🔍 Search Accounts** — Quickly find an account in your authenticator list.
- **➕ Account Management** — Add, edit, and delete authenticator accounts.
- **📤 QR Code Export** — Export supported authenticator account data through QR codes.
- **🔒 Encrypted Vault** — Protect stored authenticator data using AES-256-GCM authenticated encryption.
- **🔐 Master Password Protection** — Use a master password to unlock your encrypted vault.
- **💻 Remember on This PC** — Optionally use Windows DPAPI to protect a remembered unlock password for convenience.
- **⚙️ Security Settings** — Choose between entering your master password every time or remembering the unlock password on your PC.
- **🖥️ Desktop Application** — A graphical interface designed for Windows.
- **📦 Standalone EXE Support** — Can be packaged as a Windows executable using PyInstaller.

## 🛠️ Built With

- Python
- Tkinter — Desktop user interface
- PyOTP — TOTP code generation
- qrcode — QR code generation
- OpenCV — QR code detection and processing
- Pillow — Image processing
- Cryptography — AES-GCM encryption

## 📋 Requirements

- Windows 10 or Windows 11
- Python 3.11 or another Python version compatible with the installed dependencies
- Internet access for installing dependencies, if they are not already installed

## 🚀 Installation

### Option 1: Run from Source

**1. Clone the repository**

```bash
git clone https://github.com/ivnx9/authenticator-app-pc.git
cd authenticator-app-pc
```

**2. Install the dependencies**

```bash
py -m pip install pyotp "qrcode[pil]" opencv-python Pillow cryptography
```

**3. Run the application**

```bash
py authenticator.py
```

On the first launch, create a master password to protect your authenticator vault.

### Option 2: Run the Windows Executable

If a prebuilt Windows executable is available in the project's GitHub Releases:

1. Download the executable from the Releases page.
2. Save it to a trusted folder on your computer.
3. Run the application.
4. Create or enter your master password when prompted.

Only download releases from a source you trust.

## 🔐 Security and Privacy

Your authenticator accounts contain sensitive information. This application is designed to protect saved account data, but it cannot guarantee protection against every type of attack.

### Master Password

The app uses a master password to derive an encryption key using scrypt. The vault is encrypted with AES-256-GCM, which provides confidentiality and integrity protection.

**Important:** If you forget your master password, your encrypted vault may be permanently inaccessible. Keep a secure backup of your data and remember your password.

### Password Every Launch

This is the recommended setting for stronger protection.

- The app asks for your master password every time it starts.
- Your vault remains encrypted while stored on disk.
- You must remember your master password to unlock the vault.

### Remember on This PC

This option prioritizes convenience.

- Windows DPAPI protects the remembered unlock password for your Windows user account.
- The app can unlock the vault without asking for your password every time.
- Anyone or any malware running with sufficient access to your Windows user account may still be able to access the app or its secrets.

Use this option only on a trusted, password-protected computer.

### Protect Your Vault Files

Never upload your personal vault, backups, QR exports, or authenticator secrets to a public repository.

Keep your Windows account secure and maintain an encrypted backup in a separate, safe location.

## 📁 Local Data Storage

The application stores its vault in the following Windows location:

```text
%LOCALAPPDATA%\Authenticator\
```

The vault filename is:

```text
authenticator-data.json
```

When the Remember on This PC option is enabled, the app also stores a DPAPI-protected file for the current Windows user.

Do not share these files publicly. The vault may contain sensitive authenticator information.

## 🧑‍💻 Development

To contribute or modify the application:

1. Fork the repository.
2. Create a feature branch.
3. Make your changes.
4. Test account creation, QR import, saving, restarting, and password unlocking.
5. Submit a pull request describing your changes.

## ⚠️ Disclaimer

This project is provided for personal use and educational purposes. It has not been independently security-audited.

Although encryption helps protect stored data, it does not guarantee protection against malware, compromised Windows accounts, keylogging, memory inspection, or other attacks on an active session.

Always keep a secure backup of your authenticator accounts and ensure you can recover access to your services.

---

**Made with ❤️ using Python.**
