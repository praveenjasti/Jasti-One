# Jasti One — Architecture decisions

- Windows desktop: orchestration, selected-folder local metadata analysis, RAM/process/startup inventory and review UI.
- Gmail: Google OAuth; read-only scan first; Trash workflow later.
- iPhone: PhotoKit, Contacts and Files document picker; on-device analysis.
- USB: user-mediated iPhone media import. Do not assume unrestricted iOS filesystem access.
- Wi-Fi: future authenticated local pairing with explicit pairing code, TLS and user-approved transfer.

Jasti Cleaner holds bounded file/directory findings in memory for the active review session. The metadata inventory reads file metadata; exact duplicate verification hashes candidate groups, and the review list hashes only bounded visible candidates so they can be revalidated before quarantine. Browser profile trees remain excluded from duplicate hashing, and non-cache browser files are excluded from inventory. SQLite history stores aggregate counts and sizes only; it does not persist file names or paths.

On Windows, selected roots and directories are validated with the existing handle/reparse-point policy. The inventory enumerator pins active directory handles and checks the final handle path against the selected root. Symbolic links and junctions are skipped/rejected. Inaccessible or changed entries are counted without logging their paths. Drive capacity is metadata only; drive roots are not scannable in this milestone.

Supported temporary/browser/developer-cache/Downloads classifications are location hints, not proof that data is disposable. Browser password, cookie, payment and history files are not included. Cache files are metadata-only; no browser profile is modified.

Quarantine/restore service code models this lifecycle: scan → explicit review/selection → user confirmation → revalidate file identity, metadata and SHA-256 → same-volume no-replace rename → persist operation state → restore only after manifest, hash, identity, scope and no-overwrite checks. The UI and service operations are default-disabled until the security gate is cleared. Exact-duplicate groups retain at least one verified copy that the user did not select.

The quarantine store is `.jasti-one-quarantine` under the selected scan root so a move stays on the original volume. Cleaner inventory and duplicate scans validate and exclude this store; selecting the store itself or a descendant is rejected, and an invalid reserved store aborts the scan instead of being traversed. Each operation has a UUID directory, a strict version-1 JSON manifest, and an opaque payload name. Manifest updates use a flushed temporary file and atomic replacement. A store-wide exclusive Windows operation lock serializes list/quarantine/restore transitions. Durable states include `PREPARED`, `MOVING`, `QUARANTINED`, `RESTORING`, `RESTORED`, `FAILED`, and `RECOVERY_REQUIRED`; listing reconciles interrupted move/restore states from the original and payload identities.

Windows moves use a file handle opened with read/delete access while denying concurrent writes and renames, verify the open object and SHA-256, then issue a no-replace rename. Validated destination directories and the selected root are held open without delete sharing across the rename. The service rejects cross-volume moves because a verified copy-and-recovery protocol is not implemented. Restore refuses an existing destination and does not create missing parent directories. The application does not permanently delete files or perform automatic cleanup. Independent source review assessed destination-parent replacement and concurrent-operation controls as mitigated; runtime link testing is blocked locally. Manifests are not cryptographically authenticated against malicious same-user modification. Keep quarantine and restore disabled until the security gate is cleared.

iCloud Photos deletion can propagate across synced devices. Require a clear warning and Apple's confirmation flow.

Product branding: **Jasti One**. Windows cleanup module: **Jasti Cleaner**. The internal Python namespace remains `pdcm` during this foundation stage.
