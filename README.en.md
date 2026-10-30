English · [Русский](README.md)

# PassVault

An offline password vault and generator for Windows. One encrypted file `vault.pmv`, no clouds,
no accounts. There is a companion Android app
([PassVaultAndroid](https://github.com/Keavors/PassVaultAndroid)) with the same file format:
synchronisation is transferring the file and merging with conflict review on either side.

Current version: 3.2. The detailed history of decisions and changes per version is in
[README_PassVault.txt](README_PassVault.txt) (in Russian).

## Features

- Entries: title, login, password, URL, notes; search across all fields; history of up to 10 past passwords.
- Password generator on the OS cryptographic RNG with a configurable character set.
- Autosave a second after an edit, atomic writes verified by decryption.
- Four layers of protection against data loss: trash, password history, snapshot archive with
  grandfather-father-son rotation, and the previous file version for instant rollback.
- Merge with another vault file: differences are shown in full, deletions carry over,
  a snapshot is taken before merging, cancel rolls back everything.
- CSV/JSON export and import, understands Bitwarden and KeePass exports.
- Auto-lock, clipboard clearing after 30 seconds, growing pause after wrong passwords.
- The program writes nothing to the user profile: everything lives next to the vault.
- Networking is disabled at the process level (`pvault/netblock.py`); a system-level guarantee
  comes from a firewall rule on `PassVault.exe`.

## Install and run

**Ready installer.** Run `PassVault-Setup-<version>.exe`: no Python needed, no admin rights needed.
By default it installs on the drive the installer was started from.
Uninstall via "Settings → Apps"; the vault, rollback and snapshot archive are not deleted.

**Without installing.** Put `PassVault.exe` anywhere and run it. Installer and app are one file,
distinguished by name: `PassVault-Setup-*.exe` installs, `PassVault.exe` opens the vault.

**From source.**

```bash
pip install cryptography argon2-cffi
python passvault.py
```

Self-check: `python passvault.py --test` (automated tests), `PassVault.exe --selfcheck` (built exe).

## Build

```bash
python build.py            # flags: --skip-tests, --clean, --console
```

The script installs what is missing (PyInstaller), draws the icon, runs the tests and builds
`PassVault-Setup-<version>.exe` and `PassVault.exe` into `dist\`. If the tests fail, the build
stops. UPX is disabled on purpose: a compressed unsigned exe triggers antivirus false positives.

## Where the data lives

Everything next to the vault:

| File | What it is |
|---|---|
| `vault.pmv` | the vault |
| `vault.pmv.prev` | previous version for rollback |
| `vault.pmv.lock` | "open" marker, removed on exit |
| `vault.pmv.att` | wrong-password counter |
| `vault_backups\` | snapshot archive (the folder can be moved: Tools → Settings) |

The list of recently opened files is in `config.json` next to the program. The vault is looked for
by command-line argument, last opened path, next to the program, one level up, in "Documents"
and on the desktop.

## Protection

- Master password → Argon2id (3 passes, 256 MiB, 4 lanes), 16-byte salt → AES-256 key.
- The file is encrypted with AES-256-GCM: a wrong password, corruption or tampering gives an error, not garbage.
- Numbers from the file header are sanity-checked so a planted file cannot freeze the program.
- Only the `PMVAULT2` format (Argon2id) is written. `PMVAULT1` (PBKDF2, versions 1.x and 2.x)
  is always read and migrates to Argon2id on first open after a copy in the old format is
  placed in the archive. The master password does not change.
- The plaintext inside is JSON UTF-8 (`version`, `entries`, `settings`), timestamps in ISO-8601 UTC.
  Unknown fields from newer versions are preserved untouched.

## Backups

A snapshot is taken on save (no more than once per 5 minutes and only when the contents changed),
right after opening if the archive is empty, and before events: merge, password change, restore,
purge and import. Rotation: last 12, hourly for a day, daily for a month, monthly for a year,
event snapshots — last 10. Restoring is a merge, not a file replacement. Snapshots are ordinary
`.pmv` files and can be opened via "Open another file…".

## Synchronisation with the phone

- PC → phone: File → "Save copy as…" → file to the phone → in the app "⋮" → "Import and merge".
- Phone → PC: "⋮" → "Export copy" → file to the PC → File → "Merge with another file…".

Merge rules are the same on both sides: new entries are added, identical ones are skipped,
differences are shown with both versions and a "newer" mark, the replaced password goes to
history. To make both sides identical: merge on device A, export the result and merge on B.

## Keyboard shortcuts

`Ctrl+S` save, `Ctrl+N` new entry, `Ctrl+L` lock, `Ctrl+B` backups.

## Code layout

```
passvault.py            entry point
build.py                exe and installer build
pvault/crypto.py        container, KDF, encryption
pvault/model.py         entries, timestamps, history, tombstones
pvault/generator.py     password generator
pvault/merge.py         merging
pvault/paths.py         where the vault and its service files live
pvault/storage.py       atomic write, lock, search for copies
pvault/backup.py        snapshot archive and rotation
pvault/portable.py      CSV and JSON export/import
pvault/throttle.py      delay after wrong passwords
pvault/config.py        recent files list
pvault/session.py       the open vault: saving, merging, password
pvault/setup.py         install and uninstall
pvault/netblock.py      disabling the network
pvault/selfcheck.py     self-check of the built exe
pvault/ui/              the interface (the only layer that knows about tkinter)
tests/                  automated tests (193 checks)
tools/make_icon.py      the icon is drawn by code
tools/make_android_fixture.py   reference files for the Android tests
_legacy/                sources of 1.x and the unfinished 2.1, old README
```

Everything except `pvault/ui` knows nothing about tkinter and is tested without a single window on screen.
The tests write nothing to the user profile: temporary files go to `.testtmp` next to the project.

```bash
python -m pytest            # or python passvault.py --test
```

## Compatibility with the Android version

Checked on real files in both directions. `python tools\make_android_fixture.py` puts two
reference files (`PMVAULT2` and `PMVAULT1`) into the Android project's tests; the project path is
set by the `PASSVAULT_ANDROID_PROJECT` variable. The Android test in turn writes
`app\build\interop\android_vault.pmv`, read by `tests/test_android_interop.py`; without it these
checks are skipped.

Order when the format changes: PC tests → `make_android_fixture.py` → `gradlew :app:testDebugUnitTest` → PC tests again.
