# Jasti One Security Test Plan

**Status:** Initial implementation

## Test rules
- Use temporary directories and synthetic data only.
- Never execute destructive tests against real user files.
- Skip platform-specific junction and symlink tests when the OS does not permit creation.

## Required cases
| ID | Scenario | Test location | State |
|---|---|---|---|
| ST-001 | Windows protected roots and traversal | tests/test_path_policy.py | Protected-root tests implemented; explicit approved-workspace traversal test pending; pytest not run |
| ST-002 | Symlinks and directory links | tests/test_path_policy.py, tests/test_duplicate_engine.py | Tests implemented; pytest not run; current Windows denied symlink creation; junctions pending |
| ST-003 | Malicious quarantine manifest | TBD | Not implemented |
| ST-004 | File modification during scan | tests/test_duplicate_engine.py | Implemented; synthetic smoke passed; pytest not run |
| ST-005 | Interrupted file move | TBD | Not implemented |
| ST-006 | Unauthorized file access | TBD | Not implemented |
| ST-007 | OAuth token exposure/logging | TBD | Gmail blocked |
| ST-008 | Malicious Gmail content | TBD | Gmail blocked |
| ST-009 | Unsafe command execution | TBD | AI blocked |
| ST-010 | Repository prompt injection | TBD | AI blocked |
| ST-011 | Untrusted local network requests | TBD | Wi-Fi blocked |
| ST-012 | Restore destination overwrite | TBD | Cleanup blocked |

The security workflow includes Ubuntu security scans and a Windows filesystem test job. Hosted runs remain unverified. Release runs include unit tests, Bandit, pip-audit and manual threat-driven validation.

## Evidence recorded

- `python -m compileall -q pdcm tests` — passed using CPython 3.15.2.
- Isolated synthetic filesystem smoke script — passed for exact duplicate detection, custom-folder protected-name handling and modification during hashing. File/directory symlink creation failed with `OSError`, so those checks were not exercised.
- `python -m pytest -q` — not run successfully (`No module named pytest`).
- Package install of pytest/security tools failed because Windows Application Control blocked `pyexpat`.
- Symlink/junction/reparse-point tests, full CI, Bandit, pip-audit and SBOM generation are not verified.

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
