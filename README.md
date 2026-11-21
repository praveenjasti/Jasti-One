# Jasti One

**Your digital life, one place.**

Jasti One is a local-first digital cleanup and management platform. Its first module is **Jasti Cleaner**, focused on Windows storage analysis and user-approved, reversible quarantine. The broader product architecture includes Gmail and an iPhone companion.

Version 1.2.0 — architecture foundation

## Product structure
- **Jasti One** — overall product and desktop dashboard.
- **Jasti Cleaner** — Windows storage inventory, duplicate review, and controlled quarantine/restore.
- **Jasti Mail** — planned Gmail inventory and cleanup.
- **Jasti Mobile** — planned iPhone inventory and management companion.

## Current implementation status
- Windows desktop shell and Jasti Cleaner dashboard: implemented.
- Selected-folder storage inventory, top files/directories, file type and age/size summaries: implemented, read-only.
- Exact duplicate scan: staged size/quick-fingerprint/SHA-256 verification; no automatic selection.
- Review candidates include scan-time file identity and SHA-256 evidence; unavailable or changed files are ineligible for quarantine.
- Quarantine and restore code is present but disabled by default at both service and UI; this build remains analysis-only pending security-gate clearance.
- The disabled quarantine implementation is same-volume only, uses strict versioned manifests and no-overwrite restore, and rejects cross-volume moves. Quarantine contents are excluded from Cleaner and duplicate scans.
- Permanent deletion, automatic cleanup, and administrator elevation are not implemented.
- Temporary, browser-cache, developer-cache and Downloads classifications are limited to known locations inside the selected scan scope.
- Startup, process, RAM and drive-capacity snapshots are read-only.
- Aggregate-only local SQLite scan history is implemented.
- Drive-root scanning is not enabled. Quarantine and restore are the only file-moving operations in this milestone; no permanent cleanup is available.
- Gmail: connector boundary only; requires owner-created Google OAuth credentials.
- iPhone: SwiftUI Photos and Contacts inventory starter; requires macOS/Xcode and a physical iPhone.
- USB: user-mediated media import design; no unrestricted iPhone filesystem access.
- Wi-Fi: pairing protocol documented; transport not enabled yet.

## Safety
Analysis runs locally and is read-only and requires the user to select a folder. Quarantine and restore controls and service operations are disabled pending security-gate clearance; no files are moved by this build. No permanent deletion, automatic cleanup, telemetry, or cloud upload exists. Windows system/protected roots and reparse points are rejected; the application fails closed on changed files and untrusted manifests. Browser passwords, cookies, payment data and history are excluded from inventory and duplicate hashing. Scan history stores aggregate counts only. Logical file sizes and duplicate potential are not promises of reclaimable disk space.

## Windows setup
Windows 10/11, Python 3.11+ (the tested setup used Python 3.13):
```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\jasti-one.exe
```
Do not run as Administrator. The `pdcm` module command remains available for compatibility:
```powershell
.\.venv\Scripts\python.exe -m pdcm
```

For the Cleaner usability regression checklist, see
[`docs/JASTI_CLEANER_MANUAL_TEST_CHECKLIST.md`](docs/JASTI_CLEANER_MANUAL_TEST_CHECKLIST.md).

## iPhone setup
On macOS, create a SwiftUI iOS app target in Xcode and add the Swift files under `ios/PDCMCompanion`. Test PhotoKit and Contacts on a physical iPhone. No deletion or network pairing is implemented.

## Gmail setup
Create a Google Cloud project, enable Gmail API, configure OAuth consent and a desktop OAuth client. Keep credentials out of Git. Begin with read-only scopes; add Trash operations only after separate safety review.

## Next gates
1. Run the configured strict symbolic-link suite on an eligible Windows runner; local link creation is blocked by WinError 1314. Complete hosted CI and retain its reports.
2. Resolve remaining manifest-integrity and legal licence-review items; the current lock, pip-audit, Bandit and CycloneDX evidence is recorded in `security-reports/`.
3. Add automated/human verification for startup, process and file-category outputs across supported Windows versions.
4. Keep drive-root scanning, Docker data inspection, quarantine/restore and permanent cleanup gated until all release blockers are closed.
5. Continue Gmail, iPhone and network work only in their own reviewed milestones.

The current local test run is recorded in [`docs/IMPLEMENTATION_PROGRESS.md`](docs/IMPLEMENTATION_PROGRESS.md). Four symbolic-link tests were explicitly skipped because Windows returned `WinError 1314`; they are not counted as passed. The app is not production-ready.

## Naming note
Jasti One is the product name. PDCM remains the internal historical project/package identifier until a dedicated package migration is tested.


## Open-source assessment

See [`docs/OPEN_SOURCE_ASSESSMENT.md`](docs/OPEN_SOURCE_ASSESSMENT.md) for candidate repositories, first-pass code findings, licence gates and integration decisions. No third-party source is vendored yet.

## Security and licence compliance

Security work is mandatory and release-blocking. The current status and required controls are documented in:

- [Threat model](docs/SECURITY_THREAT_MODEL.md)
- [Vulnerability assessment](docs/VULNERABILITY_ASSESSMENT.md)
- [CVE/advisory register](docs/CVE_AND_ADVISORY_REGISTER.md)
- [Dependency security](docs/DEPENDENCY_SECURITY_REPORT.md)
- [Software bill of materials](docs/SOFTWARE_BILL_OF_MATERIALS.md)
- [Open-source licence register](docs/OPEN_SOURCE_LICENCE_REGISTER.md)
- [Licence compatibility assessment](docs/LICENCE_COMPATIBILITY_ASSESSMENT.md)
- [Security test plan](docs/SECURITY_TEST_PLAN.md)
- [Remediation tracker](docs/SECURITY_REMEDIATION_TRACKER.md)
- [Release checklist](docs/SECURITY_RELEASE_CHECKLIST.md)
- [Implementation progress and verification evidence](docs/IMPLEMENTATION_PROGRESS.md)
