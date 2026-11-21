# Jasti One

**Your digital life, one place.**

Jasti One is a local-first digital cleanup and management platform. Its first module is **Jasti Cleaner**, focused on safe Windows storage and duplicate-file analysis. The broader product architecture includes Gmail and an iPhone companion.

Version 1.2.0 — architecture foundation

## Product structure
- **Jasti One** — overall product and desktop dashboard.
- **Jasti Cleaner** — Windows storage inventory and duplicate-file analysis.
- **Jasti Mail** — planned Gmail inventory and cleanup.
- **Jasti Mobile** — planned iPhone inventory and management companion.

## Current implementation status
- Windows desktop shell: implemented.
- RAM overview: implemented.
- Exact duplicate scan: read-only SHA-256 engine included.
- Gmail: connector boundary only; requires owner-created Google OAuth credentials.
- iPhone: SwiftUI Photos and Contacts inventory starter; requires macOS/Xcode and a physical iPhone.
- USB: user-mediated media import design; no unrestricted iPhone filesystem access.
- Wi-Fi: pairing protocol documented; transport not enabled yet.

## Safety
Scans are read-only. No cleanup is performed in this foundation build. System roots are rejected for duplicate scans. Gmail credentials are not stored. iPhone data is not uploaded or deleted.

## Windows setup
Windows 11, Python 3.11+:
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install -e .
py -m pdcm
```
Do not run as Administrator. The internal Python package and launch command remain `pdcm` for compatibility; the product branding is Jasti One.

## iPhone setup
On macOS, create a SwiftUI iOS app target in Xcode and add the Swift files under `ios/PDCMCompanion`. Test PhotoKit and Contacts on a physical iPhone. No deletion or network pairing is implemented.

## Gmail setup
Create a Google Cloud project, enable Gmail API, configure OAuth consent and a desktop OAuth client. Keep credentials out of Git. Begin with read-only scopes; add Trash operations only after separate safety review.

## Next gates
1. Pin and audit upstream source commits, licenses, dependencies and tests.
2. Integrate a Windows duplicate engine behind the adapter interface.
3. Add quarantine/restore with hash verification and audit logging.
4. Add Gmail read-only scanning.
5. Test iPhone inventory and authenticated Wi-Fi pairing.
6. Add approval-based cleanup separately for each source.

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
