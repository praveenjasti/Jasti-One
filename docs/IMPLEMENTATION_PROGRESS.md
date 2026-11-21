# Jasti One Security Remediation — Implementation Progress

**Assessment date:** 21 November 2026  
**Status:** Jasti Cleaner analysis and controlled quarantine/restore are implemented locally; Windows Cleaner remains not release-ready

## Stage A — Repository baseline

- Branch: `main`; baseline commit `7f30f8d` is local and was not pushed.
- A separate baseline backup was created outside the repository. Its machine-specific location is intentionally omitted from publishable documentation.
- Before Milestone 2 edits, a worktree backup was verified against all 47 included files by SHA-256; baseline HEAD was `7f30f8d38fad43f7857961260cb0dbd8c2d4d04f`. The Git metadata was not copied.
- Structure: Python 3.11+ / PySide6 desktop package (`pdcm`), two pytest modules, SwiftUI iOS starter, GitHub workflows and security/architecture documents.
- Existing functionality: RAM summary; read-only duplicate scanner; Gmail connector intentionally disabled; iOS Photos/Contacts read-only starter.
- At this recorded baseline, quarantine/restore and user-approved cleanup were absent; dependency lock, scan, SBOM, licence evidence and hosted CI were also unverified.

## Stage B — Filesystem security

**Implemented; source-reviewed and locally exercised, with symbolic-link verification blocked**

- Converts the user-selected root to an absolute path, rejects root components that are symbolic links/reparse points, and rejects protected Windows roots.
- Avoids resolving the selected Windows root before its component handles are acquired; applies protected-root checks to the handle-derived canonical path after acquisition.
- On Windows, opens each selected-root path component and holds its handle without delete sharing; opens active directories with `FILE_FLAG_OPEN_REPARSE_POINT` while enumerating.
- Opens discovered files with `FILE_FLAG_OPEN_REPARSE_POINT`, checks their final handle paths remain under the selected root, and retains the discovered file signature across fingerprint and hash reads.
- Keeps the Windows traversal read-only and refuses reparse points; a concurrent directory-to-junction replacement is skipped rather than followed.
- Preserves the existing non-Windows traversal behavior and skips file/directory reparse points there.
- Compares stable file identity fields across Windows path/handle stats and compares change time between path stats; this avoids false rejection caused by this runtime's differing `lstat()`/`fstat()` `st_ctime_ns` values.
- Reports inaccessible or changed entries through path-free warnings.

**Remaining risks / blockers**

- Windows symbolic-link creation remains blocked with `WinError 1314`; all six related tests are reported as skipped in the normal suite and fail explicitly in strict mode. Junction-root, traversal-confinement, replacement and post-handle rename-blocking tests passed locally.
- VA-001 remains open pending hosted symbolic-link verification. Independent source review confirmed Windows returns the lexical root before the non-Windows `Path.resolve()` path and that path components/active directories are pinned without delete sharing. The traversal uses `os.scandir` while handles pin path components; it does not use native handle-relative directory enumeration.
- Root handle acquisition can fail under restrictive ACL or sharing conditions; such failures abort rather than returning success-shaped empty scan results.
- The selected root is per scan, not a separately configured application-wide workspace allowlist.

## Stage C — Controlled quarantine and restore

**Implementation present; independent source review completed; all file moves remain disabled**

- Added independent `QuarantineService` with a versioned, strictly validated manifest and per-operation state under `.jasti-one-quarantine` in the selected scan root.
- Review candidates carry scan-time file identity/signature and SHA-256. Only bounded visible findings and verified duplicate members are hashed; candidates without valid evidence cannot be selected.
- Added explicit checkbox selection and confirmation. No file is selected automatically. Exact duplicate groups must retain at least one unselected copy, and that survivor is revalidated before moving selected copies.
- On Windows, opens the selected file with read/delete access while denying concurrent writes/renames; checks handle identity, metadata and content hash; holds validated destination directory handles without delete sharing across no-replace renames. Existing destinations are never overwritten.
- The quarantine store is excluded from Cleaner and duplicate scans; selecting it or a descendant as a scan root is rejected. A malformed reserved store aborts the scan rather than being traversed.
- Restore validates operation/store identifiers, schema, selected-root scope, payload identity, size, timestamp and hash; it requires explicit approval and refuses an existing destination.
- Atomic manifest replacements persist `PREPARED`, `MOVING`, `QUARANTINED`, `RESTORING`, `RESTORED`, `FAILED`, and `RECOVERY_REQUIRED` states. Listing reconciles interrupted states; ambiguous operations block additional quarantine.
- Cross-volume movement is rejected with a user-facing error. No copy fallback, permanent deletion, automatic cleanup, quarantine purge, or administrator elevation was implemented.
- Tests use synthetic temporary files only. Local Windows tests exercise round-trip restore, changed file rejection, external-junction rejection, malicious/out-of-scope/path-traversal manifests, payload tampering, duplicate keeper preservation, interruption reconciliation, and no-overwrite races.
- Independent source review confirmed destination-parent replacement and cooperative concurrency mitigations, but found a separate VA-002 source-parent replacement race: nested source-parent handles are not held through the later handle-based move, so a timed parent rename can move the pinned source outside the selected root. A same-user writer can also coherently modify an unauthenticated manifest and payload. The UI and service move gates are default-off; no user files were moved during tests.
- Residuals: the VA-002 source-scope race and VA-009 same-user manifest/payload authenticity remain open. Windows symbolic-link test execution remains blocked locally by `WinError 1314`; hosted test execution is unavailable until authorized publication to GitHub.

## Stage D — Dependency/CVE/SBOM evidence

**Executed locally; hosted run and complete manual advisory review remain blocked.**

- `requirements.lock` resolves 80 exact packages with 1,059 SHA-256 hashes, including `setuptools==84.2.1` needed by the build backend. A clean hash-required install, editable install, `pip check`, and hash dry-run passed on Python 3.13.17.
- pip-audit 2.10.1 ran against the installed and locked graphs: 84 installed records and 81 lock records, zero reported vulnerabilities in both. The initial lock report retained `lxml==5.4.0` with CVE-2026-41066 / GHSA-vfmq-68hx-4jfw / PYSEC-2026-87; current lock resolves `lxml==6.1.3`.
- Bandit 1.9.4 completed with zero findings over 3,618 LOC.
- CycloneDX generated an 83-component/84-dependency SBOM; strict CycloneDX 1.6 JSON validation passed. Two packages lack license metadata.
- A targeted follow-up compared the known lxml findings against the NVD API, GHSA, OSV, and lxml vendor notes. CVE-2026-41066 is fixed in 6.1.0; vendor issue LP#2165901 is marked fixed in 6.1.3, the current lock version. This is not a full package-by-package advisory review. The tools do not establish absence of unknown vulnerabilities or reachability for every package.

## Stage E — Licence compliance

**Metadata inventory generated; legal and final-package review remain blocked.** The SBOM inventory records 83 components, with license metadata for 81; protobuf 7.36.2 and uritemplate 4.2.0 are unknown. The six installed Qt distributions declare an LGPL/GPL alternative expression and each contains a commercial-license reference file, but no complete Qt/Chromium notice bundle was found in the installed package tree. The dependency closure includes Qt WebEngine and PDF native components; the exact installer contents and licensing path are not established. Commercial distribution remains blocked.

## Stage F — CI verification

**Configured locally, not hosted or verified.** The security workflow covers Ubuntu scans and strict Windows link tests on `windows-2025`, records Windows privilege information, retains full reports, and pins action references to commit SHAs. The configured public remote `praveenjasti/Jasti-One` reports zero workflows and zero runs. No source was pushed because publishing the worktree would make it public; owner authorization is required. No hosted run URL or artifact is claimed.

## Stage G — Windows Cleaner MVP

**Implemented, locally tested; not production-ready**

- Added the Jasti Cleaner page to the existing PySide6 desktop app. The user must choose a folder before scanning; inventory and duplicate work run on a cancellable background thread with visible progress, errors and completion summaries.
- Added read-only folder/file metadata inventory, folder totals (largest 100), largest/old file review (bounded lists), extension/type totals, 100/500/1,024 MiB thresholds, 30/90/180 day filters, and video/archive/installer/disk-image filters.
- Reused the existing selected-root/reparse-point policy and Windows handle-guarded traversal for inventory. Directory junctions are rejected/skipped, active directory handles prevent the tested rename race, and changed/inaccessible entries are omitted and counted.
- Reused the staged duplicate scanner with cancellation. Exact matches require SHA-256; browser profile roots are excluded from duplicate hashing. Hard-link aliases remain visible in groups but do not inflate potential duplicate bytes.
- Temporary, browser-cache, developer-cache and Downloads classifications are location hints only within the selected root. Sensitive browser Cookies, History, Login Data and Web Data files are excluded from inventory; only recognized cache subdirectories receive metadata inspection.
- Added read-only drive capacity, startup registry/folder, process, RAM and CPU snapshots. Startup/process details are refreshed when the corresponding tab is opened or explicitly refreshed; commands are never executed.
- Added SQLite scan history containing aggregate counters only. Full selected paths, file names and file contents are not stored.
- Added settings/status text explaining local analysis and explicit reversible quarantine. There is no permanent deletion, automatic cleanup, telemetry, or cloud-upload operation.
- Drive roots remain rejected by the existing root policy; users can select an allowed folder on a drive. Docker data is not inspected because it may contain persistent container/volume data and no service interaction is enabled.
- The metadata inventory uses bounded top-file, category, extension and directory summaries; the existing duplicate engine retains candidate metadata proportional to files in the selected scope, so unusually large scans may use substantial memory. Cancellation is supported, but no resource budget is enforced yet.
- Updated the PySide6/psutil exact pins to `PySide6==6.12.0` and `psutil==7.2.2` after the previous PySide6 6.7 pin prevented installation on Python 3.13. The full Python 3.13 lock and automated audit/SBOM evidence are now recorded in Stage D; source-level license and commercial distribution review remain open.

### MVP feature status
| Feature | Status |
|---|---|
| Folder storage, largest directories/files, types, old/large filters | Implemented and tested |
| Exact duplicate groups and potential bytes | Implemented and tested; no copy is selected automatically |
| Temporary/browser/developer/Downloads classification | Implemented and tested for known locations within selected scope |
| Startup/process/RAM/CPU/drive-capacity overview | Implemented; system snapshots are read-only; platform breadth not fully verified |
| Cancellation, progress, inaccessible/change handling | Implemented and tested |
| Aggregate-only SQLite history | Implemented and tested |
| Symbolic-link coverage | Fail-closed behavior implemented; six link-creation tests blocked locally by `WinError 1314`; strict run confirms environment block |
| Whole-drive scanning | Not implemented; drive roots remain protected by the existing policy |
| Quarantine/restore | Implemented behind default-off UI/service gates; synthetic tests pass, but release-blocked by the source-parent race, manifest authenticity and missing hosted symlink evidence |
| Cross-volume quarantine, permanent cleanup, quarantine purge | Not implemented; cross-volume moves are rejected |
| Gmail/iPhone/USB/Wi-Fi/AI/updater | Not part of this milestone |

## Validation evidence

| Command/check | Result |
|---|---|
| `<locked-env>\Scripts\python.exe -m pip install --require-hashes -r requirements.lock` | Passed in the clean Python 3.13.17 environment; 80 locked packages |
| `<locked-env>\Scripts\python.exe -m pytest -q -ra --junitxml=security-reports/test-results-local.xml` | Windows 11 Home Single Language / Python 3.13.17: **65 collected, 59 passed, 0 failed, 6 skipped**. Every skip is a symlink creation failure with `WinError 1314`; not counted as a pass |
| `<locked-env>\Scripts\python.exe -m compileall -q pdcm tests` | Passed |
| `<locked-env>\Scripts\python.exe -m pip check` | `No broken requirements found.` |
| Offscreen `MainWindow` event-loop launch and `grab().save(...)` | Passed; captured a 1280×900 screenshot with Segoe UI loaded for rendering. Visual/native-interactive UX still needs a normal Windows desktop review |
| Strict link retry | **6 failed at fixture setup** with `WinError 1314`; full output retained in `security-reports/symlink-strict-local.txt`. No symlink test passed |
| Junction/concurrent traversal tests | Passed locally, including external target confinement, directory replacement, and rename attempt after the directory handle was acquired |
| pip-audit installed and lock graph | Both commands exit 0; 84/81 records; 0 known vulnerabilities. JSON evidence in `security-reports/` |
| Bandit 1.9.4 | Previous and current run exit 0; 0 findings; 3,618 LOC; latest JSON evidence in ignored `security-reports/bandit-current.json` |
| CycloneDX SBOM | 83 components/84 dependency entries; CycloneDX 1.6 validation passed; output and license CSV in `security-reports/` |
| Hashed lock install / `pip check` / hash dry-run | Passed; 80 pins and 1,059 hashes; no broken requirements |
| Hosted GitHub Actions | Not run; remote currently has 0 workflows/0 runs. No hosted URL/artifact exists |

The smoke script is not committed as a test runner; it is not a substitute for pytest or junction tests. No production-readiness or vulnerability-free claim is made. Automated Python 3.13 scans and the SBOM are complete for the tested environment; eligible hosted Windows symlink testing, hosted CI, full advisory review, complete source/license/Qt asset review, the VA-002 source-scope race and VA-009 same-user manifest-integrity threat remain open.
