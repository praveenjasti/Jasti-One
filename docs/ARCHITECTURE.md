# Jasti One — Architecture decisions

- Windows desktop: orchestration, local disk analysis, RAM inventory and review UI.
- Gmail: Google OAuth; read-only scan first; Trash workflow later.
- iPhone: PhotoKit, Contacts and Files document picker; on-device analysis.
- USB: user-mediated iPhone media import. Do not assume unrestricted iOS filesystem access.
- Wi-Fi: future authenticated local pairing with explicit pairing code, TLS and user-approved transfer.

Every scan should create immutable candidate records with source, identifier/path, size, hash if applicable, scan timestamp and confidence.

Cleanup lifecycle: scan → preview → keep-one-per-group invariant → revalidate → quarantine/Recycle Bin/Recently Deleted where supported → verify → audit log → restore path where supported.

iCloud Photos deletion can propagate across synced devices. Require a clear warning and Apple's confirmation flow.

Product branding: **Jasti One**. Windows cleanup module: **Jasti Cleaner**. The internal Python namespace remains `pdcm` during this foundation stage.
