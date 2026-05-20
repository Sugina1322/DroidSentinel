# DroidSentinel

**DroidSentinel is a Windows desktop Android security hardening console powered by ADB.**

It audits Android privacy exposure, detects telemetry-heavy packages, reviews sensitive app permissions, applies hardening actions, configures Private DNS filtering, and exports reports. No mobile app is required.

## Features

- Device overview: ADB status, model, Android version, security patch, Private DNS status
- Telemetry audit: detect known OEM, ad, analytics, and vendor telemetry packages
- App permission audit: review camera, microphone, location, contacts, SMS, phone state, overlay, and usage access
- Actions: disable/uninstall packages, deny supported permissions, uninstall user apps
- Private DNS: set AdGuard DNS, Quad9, Cloudflare Security, or a custom provider
- History: per-device action log with rollback where supported
- Reports: export JSON and HTML audit reports
- Bundled ADB support through `tools\platform-tools`

## Android Setup

1. Enable **Developer Options** by tapping **Build number** seven times.
2. Enable **USB debugging**.
3. Connect the phone by USB.
4. Accept the RSA debugging prompt on the phone.
5. Run a scan in DroidSentinel.

If the phone is not detected, use a USB data cable, unlock the phone, switch USB mode to File Transfer, or install the manufacturer USB driver.

## Run

```powershell
npm.cmd install
npm.cmd start
```

## Build

```powershell
npm.cmd run pack
npm.cmd run dist
```

## Safety Note

DroidSentinel is not an antivirus. It detects and hardens Android privacy/security risks visible through ADB.

Some actions can affect app or OEM behavior. Review command previews before applying changes. User app uninstall actions may require manual reinstall.
