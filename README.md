# DEVADARA

An offline, privacy-first antivirus for Windows.

DEVADARA runs 100% on your computer. Nothing is uploaded, there are no online virus lookups, and it never deletes a file without your confirmation.

Project page: https://www.chavindujayawardana.com.lk/devadara

## Download

Go to the [latest release](https://github.com/chavindujayawardhana-pixel/devadara-releases/releases/latest) and download `DEVADARA-1.0.0-win64.zip` (about 115 MB).

## How to run

1. Right-click the zip and choose **Extract All**.
2. Open the extracted folder.
3. Run `DEVADARA.exe` inside it.

Do not run it from inside the zip. The whole folder is needed.

## Windows SmartScreen warning

DEVADARA is new software from an independent developer and is not signed with a paid Microsoft-recognised certificate yet. Windows SmartScreen may show "Windows protected your PC" or "Unknown publisher". This is expected. Download it only from this page or from my website, then choose **More info**, then **Run anyway** if you trust it.

DEVADARA checks its own files against a digitally signed list (Ed25519) and warns you if anything has been changed. You can see the result under Settings > About.

## Check your download

The SHA256 of `DEVADARA-1.0.0-win64.zip` is:

53D1A6619FDA540E93E1213CC9053A81AD29C83D856D99F46BA57B09667BA865

To check it on Windows, open PowerShell and run:

Get-FileHash .\DEVADARA-1.0.0-win64.zip -Algorithm SHA256

## Limits

- It watches the Downloads folder and USB drives, and only while the app is running.
- It does not scan inside zip files yet.
- False alarms are possible.
- It is a new, independent project and not a replacement for a mature commercial antivirus.
