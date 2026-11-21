# Jasti One Security Test Plan

**Status:** Local Windows suite and security tools executed; eligible symlink and hosted CI evidence remain blocked

## Test rules
- Use temporary directories and synthetic data only.
- Never execute destructive tests against real user files.
- When platform permissions prevent creating a link, report the test as skipped with the exact error; do not treat it as passed.

## Required cases
| ID | Scenario | Test location | State |
|---|---|---|---|
| ST-001 | Windows protected roots and traversal | tests/test_path_policy.py, tests/test_duplicate_engine.py | Protected-root and external-junction confinement tests passed. Independent review verified the Windows path does not resolve the selected root before handle validation. Six symlink tests remain unexecuted because link creation is blocked locally |
| ST-002 | Symlinks and directory links | tests/test_path_policy.py, tests/test_duplicate_engine.py | Junction root, scan, directory replacement, and post-handle rename-blocking tests passed. Strict symlink run failed during link creation with WinError 1314; no symlink behavior passed |
| ST-003 | Malicious quarantine manifest | tests/test_quarantine.py | Pass: strict field/schema validation, path traversal and out-of-scope restore destinations rejected; modified payload hash rejected |
| ST-004 | File modification/replacement during scan or before quarantine | tests/test_cleaner_engine.py, tests/test_quarantine.py | Pass: changed scan entries are omitted; changed-after-scan candidates are rejected |
| ST-005 | Interrupted file move/restore | tests/test_quarantine.py | Pass: persisted MOVING state reconciles before/after rename; ambiguous state is RECOVERY_REQUIRED |
| ST-006 | Unauthorized/out-of-root file access | tests/test_quarantine.py | Pass: candidate through an external directory junction is rejected and target remains unchanged |
| ST-007 | OAuth token exposure/logging | TBD | Gmail blocked |
| ST-008 | Malicious Gmail content | TBD | Gmail blocked |
| ST-009 | Unsafe command execution | TBD | AI blocked |
| ST-010 | Repository prompt injection | TBD | AI blocked |
| ST-011 | Untrusted local network requests | TBD | Wi-Fi blocked |
| ST-012 | Restore destination overwrite | tests/test_quarantine.py | Pass: existing destination and destination created during restore are never overwritten |
| ST-013 | Read-only inventory, no file mutations | tests/test_cleaner_engine.py | Pass: content, size, and modification time snapshots unchanged |
| ST-014 | Size/age/type and location classification | tests/test_cleaner_engine.py | Pass: synthetic files; no cleanup inference from age/size |
| ST-015 | Cancellation, inaccessible entries, modification and replacement | tests/test_cleaner_engine.py | Pass: cancellation is raised; changed entries are counted and omitted |
| ST-016 | Browser profile privacy boundary | tests/test_cleaner_engine.py | Pass: cache metadata only; Cookies, History, Login Data and Web Data excluded from scan and duplicate hashing |
| ST-017 | Aggregate-only scan history | tests/test_cleaner_engine.py | Pass: schema contains no scan-root or file-path column |
| ST-018 | Review/approval and destructive-action boundary | tests/test_cleaner_ui.py, tests/test_quarantine.py | Pass: quarantine/restore UI and service operations default disabled; no permanent delete or automatic-cleanup path |
| ST-019 | Duplicate keeper preservation | tests/test_quarantine.py | Pass: service rejects selection of every copy and re-verifies a remaining copy before moves |
| ST-020 | Quarantine scan exclusion | tests/test_quarantine.py | Pass: Cleaner inventory and duplicate scan do not traverse the managed quarantine; selecting a store descendant is rejected; malformed reserved store aborts |
| ST-021 | Cross-volume move rejection | tests/test_quarantine.py | Pass: simulated mismatched native volume identity is rejected before creating an operation or moving the source; no physical second-volume mount was available |
| ST-022 | Source-parent replacement after file validation and before quarantine rename | tests/test_quarantine.py | Required; independent review found nested source parents are not pinned through the move. No deterministic runtime test exists; quarantine remains gated off |

The security workflow includes Ubuntu security scans and strict Windows filesystem tests. It has not been published or run on GitHub: the remote reports zero workflows and zero runs. No hosted result is claimed.

## Evidence recorded

- `<locked-env>\Scripts\python.exe -m compileall -q pdcm tests` — passed.
- `...python.exe -m pytest -q -ra --junitxml=security-reports/test-results-local.xml` — **65 collected: 59 passed, 0 failed, 6 skipped**, Windows 11 Home Single Language (10.0.26300, build 26300), CPython 3.13.17 / pytest 9.0.3. All six skips are symbolic-link creation failures with `WinError 1314: A required privilege is not held by the client`. The full JUnit result is retained in `security-reports/test-results-local.xml`.
- Strict retry: `JASTI_REQUIRE_SYMLINK_TESTS=1 ... pytest -q -ra -k 'symlink or symbolic_link'` — **6 failed at fixture setup**, each because Windows returned WinError 1314; the complete output and JUnit record are retained as `security-reports/symlink-strict-local.txt` and `test-results-symlink-strict-local.xml`. These are environment-blocked tests, not passing link checks.
- `whoami /priv` did not list `SeCreateSymbolicLinkPrivilege`; Windows is Home Single Language. This environment cannot certify symlink behavior.
- The suite exercises directory junction confinement, directory-to-junction replacement, post-handle rename blocking, protected-root checks, metadata modification/replacement, cancellation, inaccessible-entry handling, browser-profile exclusion, hard-link accounting, read-only analysis, aggregate history, disabled quarantine UI/service gates, synthetic same-volume quarantine/restore, manifest validation, interruption reconciliation, and restore no-overwrite behavior.
- Offscreen PySide6 launch/render: `QT_QPA_PLATFORM=offscreen` with Python 3.13.17; the actual `MainWindow` event loop exited successfully and captured the Cleaner dashboard at 1280×900. The screenshot is a visual smoke check, not a substitute for interactive Windows UX testing.
- `py -3.14 -m compileall -q pdcm tests` — passed on Python 3.14.10.
- `pip-audit --local` and `pip-audit -r requirements.lock` — both exit 0 with no known vulnerabilities; JSON reports retained under `security-reports/`.
- Bandit 1.9.4 — exit 0, 0 findings, 3,618 LOC; JSON report retained.
- CycloneDX Python tool — generated the locked-environment SBOM; CycloneDX 1.6 strict schema validation passed, 83 components/84 dependency entries. SBOM and license metadata CSV retained.
- Hash-required lock install, editable project installation, `pip check`, and hash dry-run — passed in a clean Python 3.13 environment. The lock contains 80 pinned packages and 1,059 SHA-256 hashes.
- Independent source review corrected the apparent Windows `Path.resolve()` race finding and assessed quarantine destination-parent and concurrent-operation controls as mitigated by held no-delete-share handles and an exclusive store lock. Manifest authenticity remains a confirmed same-user threat-model limitation.
- Quarantine and restore tests use synthetic files under pytest temporary directories only. No real user file was moved.
- The original Python 3.15.2 environment could not load `pyexpat` under Windows Application Control. Tests ran in a separate Python 3.14.10 per-user environment after its official installer hash was verified by `winget`.
- Hosted GitHub Actions remain unverified: the public remote `praveenjasti/Jasti-One` currently has 0 workflows and 0 runs. Publishing the local changes would expose source to the public; no push was attempted.
- NVD/GHSA/vendor-by-vendor manual review, actual upstream license/NOTICE file capture for all packages, Qt native component inventory, and commercial Qt license decision remain incomplete.

## Milestone completion gate

No feature milestone is complete until the applicable manual review and test cases are recorded. Automated scanner success alone is insufficient, especially for:

- Path canonicalization and protected-workspace enforcement.
- TOCTOU and file modification between validation and use.
- Junction and symbolic-link traversal.
- Destructive operations and restore overwrite behavior.
- OAuth consent, token storage and log exposure.
- Gmail content as untrusted AI input.
- AI command and tool authorization.
- Local network authentication and rate limiting.
- Memory and responsiveness for very large directory trees; the duplicate engine currently retains candidate metadata proportional to the selected scope.
