# Jasti One Security Remediation — Implementation Progress

**Assessment date:** 21 November 2026  
**Status:** In progress; Windows Cleaner MVP is not release-ready

## Stage A — Repository baseline

- Branch: `main`.
- Git worktree reported all project files as untracked. They were treated as pre-existing user content and preserved; no cleanup or reset was performed.
- Structure: Python 3.11+ / PySide6 desktop package (`pdcm`), two pytest modules, SwiftUI iOS starter, GitHub workflows and security/architecture documents.
- Existing functionality: RAM summary; read-only duplicate scanner; Gmail connector intentionally disabled; iOS Photos/Contacts read-only starter.
- Blockers: no quarantine/restore or user-approved cleanup flow; no verified dependency lock, scan, SBOM, licence evidence or hosted CI run.

## Stage B — Filesystem security

**Implemented, partially verified**

- Canonicalizes the selected root, rejects root components that are symbolic links/reparse points, and rejects protected Windows roots.
- Uses the explicitly selected scan root as the scan boundary; skips file and directory reparse points during traversal.
- Verifies opened file identity and metadata around fingerprint and hash reads; files changed during a scan are not reported as duplicates.
- Compares stable file identity fields across Windows path/handle stats and compares change time between path stats; this avoids false rejection caused by this runtime's differing `lstat()`/`fstat()` `st_ctime_ns` values.
- Reports inaccessible or changed entries through path-free warnings.

**Remaining risks / blockers**

- The current Windows environment denied file and directory symlink creation with `OSError`; link rejection was therefore not runtime-tested. Junction behavior has not been tested on a supported Windows matrix.
- Path-based directory traversal remains vulnerable to a concurrent directory-to-junction replacement race; robust handle-relative traversal is not implemented. This remains release-blocking.
- The selected root is per scan, not a separately configured application-wide workspace allowlist.
- Reparse checks and file-change handling need the formal pytest suite and Windows junction tests.

## Stage C — Quarantine and restore

**Not implemented.** The app remains read-only. No manifest, quarantine, restore, or cleanup control is enabled. Do not implement/enable destructive behavior until the filesystem isolation and recovery tests can be run and reviewed.

## Stage D — Dependency/CVE/SBOM evidence

**Blocked.**

- `pyproject.toml` lists selected direct packages. `requirements.in` is a direct input, not a lockfile; transitive versions and hashes are missing.
- The selected local environment is CPython 3.15.2 and initially contained only pip 26.3. Installing pytest and scanner tools failed when Windows Application Control blocked loading `pyexpat`.
- Individual OSV version queries found pytest 8.0.0 affected by CVE-2025-71176 / GHSA-6w46-j5rx-g56g; the fixed release listed by the advisory is 9.0.3. Pytest was updated to that version, and exact OSV queries for corrected package pins returned no records. The fix is not installed or re-scanned. This is not a transitive scan or a vulnerability-free claim.
- Two initially configured package versions did not exist on PyPI (`google-api-python-client==2.120.1`, `cyclonedx-bom==4.3.1`); after checking PyPI release metadata, they were corrected to published versions 2.120.0 and 4.3.0.
- PyPI package metadata was checked for the selected direct dependencies and PySide6's three pinned package components. This does not substitute for inspecting distributed licence files or native package contents.
- No complete pip-audit result, resolved dependency graph, or SBOM was produced.
- Workflow commands are configured but have not been verified by a hosted run.

## Stage E — Licence compliance

**Blocked / requires legal review.** PyPI metadata for direct packages and the PySide6 6.7.0 Qt subpackages was checked; Qt's official LGPL/GPL/commercial guidance was reviewed. Actual wheel licence files, full transitive licences, native Qt/Windows library and asset inventory, and the final Qt packaging method remain unverified. Commercial distribution remains blocked pending technical evidence and legal approval.

## Stage F — CI verification

**Configured, not verified.** Security workflow covers Ubuntu scans plus Windows tests; CodeQL workflow exists. GitHub Actions references are pinned to full commit SHAs obtained from the upstream GitHub API, and Dependabot is configured to update GitHub Actions weekly. The lock-integrity job intentionally fails until a complete `requirements.lock` with hashes is generated and passes pip's dry-run check. No successful workflow run was available. Secret-scanning evidence is still absent.

## Stage G — Windows Cleaner MVP

**Not implemented as an MVP.** The desktop shell and read-only duplicate engine exist, but the UI does not provide storage, temporary/browser/developer-cache, large-file or startup inventory, nor quarantine/restore. Gmail, AI tools, Wi-Fi pairing and the updater remain disabled or unimplemented.

## Validation evidence

| Command/check | Result |
|---|---|
| `C:\Users\jasti\AppData\Roaming\uv\python\cpython-3.15.2-windows-x86_64-none\python.exe -m compileall -q pdcm tests` | Passed |
| Isolated PowerShell-to-Python temporary-directory smoke script | Passed 5 assertions for protected roots, custom-folder protected-name handling, exact duplicate detection and modification during hashing; symlink creation failed with `OSError`, so link checks were not exercised |
| Defined tests in `tests/` | 12 tests (6 duplicate-engine, 6 path-policy); pytest execution count: 0 |
| `.\.venv\Scripts\python.exe -m pytest -q` | Blocked: `No module named pytest` |
| `pip install pytest==8.0.0` | Failed: Windows Application Control blocked `pyexpat` DLL loading |
| `.\.venv\Scripts\python.exe -m pip_audit --local` | Not run: `pip_audit` is not installed |
| `.\.venv\Scripts\python.exe -m bandit -q -r pdcm` | Not run: Bandit is not installed |
| CycloneDX SBOM generation | Not run; no SBOM artifact exists |
| Windows symlink/junction tests / hosted GitHub Actions | Symlink creation unavailable; junction tests not run / no verified CI run |

The smoke script is not committed as a test runner; it is not a substitute for pytest or junction tests. No production readiness or vulnerability-free claim is made.
