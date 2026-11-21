# Jasti One Security Gate Report

**Assessment date:** 21 November 2026  
**Decision:** Not cleared for release or for enabling quarantine/restore.  
**Scope:** Current Windows filesystem traversal, quarantine/restore review, hosted CI readiness, dependency evidence and Qt licensing. No files were moved during this assessment; no commit or push was made.

## Gate status

| Finding | Severity | Status | Evidence | Remaining risk / required owner decision | Release-blocking |
|---|---|---|---|---|---|
| VA-001 — Symlink/junction traversal | High | Open | Local Windows 11 Home Single Language, build 26300, CPython 3.13.17: 65 collected, 59 passed, 6 skipped, 0 failed. All six skips are `WinError 1314` at symlink creation; strict retry failed all six during setup. Junction confinement and post-handle rename tests passed locally. | Workflow targets `windows-2025`, enables strict mode, records `whoami /priv`, and retains full artifacts. No GitHub workflow has run; the runner's actual symlink capability is unproven. Owner must authorize publication/triggering; a completed job must show link tests passed rather than skipped. Native handle-relative enumeration remains a possible hardening limitation. | Yes |
| VA-002 — Quarantine source-scope race | Medium | Open; independent source review | Review found `_open_move_file` checks the opened file's final path, but nested source-parent handles are not held through the later handle-based rename. A timed parent rename can move the pinned source outside the selected scan root. Confidence 8/10. Destination-parent and store-lock controls mitigate separate races. | Keep moves disabled. Engineering must bind the move to validated source parents (held no-delete-share handles or equivalent handle-relative operation) and add a race test. The exact race has not been runtime-reproduced. | Yes, before quarantine enablement |
| VA-009 — Manifest/payload authenticity | Medium | Confirmed residual | Strict schema/path/identity/size/hash checks do not authenticate the manifest and payload as a pair. A same-user writer with access to both can forge a permitted restore record and payload; independent-review confidence 9/10. | Owner must either explicitly exclude and accept malicious same-user code in the threat model, or fund a separate trusted authority and carefully constrained IPC. DPAPI CurrentUser, same-user HMAC, ordinary ACLs and same-user logs do not provide that boundary. Keep quarantine and restore disabled. | Yes, before quarantine/restore enablement |
| Hosted CI | High | Prepared, not executed | GitHub Actions API reports 0 workflows and 0 runs for `praveenjasti/Jasti-One`. Workflow is configured for `windows-2025`, strict symlink mode, environment/privilege evidence, and full `security-reports/*` artifact retention. | Remote is public. Owner authorization is required before publishing any commit. No run URL or artifact exists. | Yes |
| Dependency scans and SBOM | Medium | Local scans rerun; broad review remains open | Current pip-audit: exit 0, 84 installed records/0 vulnerabilities and 81 lock records/0 vulnerabilities. Bandit: exit 0, 0 findings, 3,618 LOC. Existing SBOM validates with 83 components/84 dependency entries. Lock SHA-256 `64D52B0ACB5CD6A01AD17C7A231BE8706632F5FD08AF514950E589D05BCDF4D8`; preserved SBOM SHA-256 `5A1D7DEB3FB1A2D1B0E290EADB71844BF27836BF09D8BC92E84DA77CC3C0C58F`. | NVD API, GHSA and OSV agree that CVE-2026-41066 is fixed in lxml 6.1.0; vendor Launchpad/release notes mark LP#2165901 fixed in 6.1.3. The lock resolves 6.1.3. These targeted checks do not constitute a manual review of all packages. The two SBOM license fields remain unknown: protobuf 7.36.2 and uritemplate 4.2.0. | Yes, pending broad review |
| Qt commercial/open-source licensing | High | Blocked pending legal and package review | Six installed Qt distributions declare `LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only`. Each contains only the same 470-byte `LicenseRef-Qt-Commercial.txt` among license/notice-named files. Installed tree: 3,893 files, 349 DLLs, 61 `.pyd`s and 18 executables, including Qt WebEngine/Chromium resources and PDF libraries. `PySide6` wheel dependencies include Essentials, Addons, WebEngine and PDF. | No exact final installer contents or version-matched Chromium third-party notice bundle has been established. Owner/legal counsel must choose and approve a Qt licensing route, confirm source/relinking/notice obligations, and approve distribution. | Yes |

## Threat-model decisions

- **Accidental manifest corruption:** strict validation, hashes and durable states can detect malformed or inconsistent data; backup/atomic replacement and operational recovery reduce accidental loss. These controls do not establish provenance.
- **Another Windows account:** restrictive ACLs and a user-scoped key can reduce access by other accounts if correctly configured. No ACL or DPAPI deployment boundary has been implemented or verified here.
- **Malicious code running as the same user:** a same-user HMAC key or DPAPI `CurrentUser` key can generally be used by that code; neither is an independent authority. A TPM non-exportable key may prevent extraction but does not prevent same-user use of an authorized signing operation.
- **Administrator or application compromise:** ordinary user ACLs and same-user cryptography do not protect against a local administrator or compromise of the application process. A separate-principal broker with narrow authenticated IPC could add a boundary but creates privilege/confused-deputy risks and is not implemented.
- **Recommended current decision:** do not enable quarantine or restore. If the product will not defend against malicious code running as the same user, the owner must explicitly accept and document that exclusion; this does not waive VA-002's source-scope race.

## Publication boundary

The local branch is `main` at baseline commit `7f30f8d38fad43f7857961260cb0dbd8c2d4d04f`; the remote `origin` is `https://github.com/praveenjasti/Jasti-One.git`. The GitHub repository is public. The worktree is dirty and no files are staged; pushing the baseline SHA would not publish the worktree changes. A new commit would be required to publish them. No commit, push or visibility change was made.

If publication is later authorized, the current intended source allowlist is exactly:

```
.gitignore
.github/workflows/security.yml
README.md
docs/ARCHITECTURE.md
docs/CVE_AND_ADVISORY_REGISTER.md
docs/DEPENDENCY_SECURITY_REPORT.md
docs/IMPLEMENTATION_PROGRESS.md
docs/LICENCE_COMPATIBILITY_ASSESSMENT.md
docs/OPEN_SOURCE_LICENCE_REGISTER.md
docs/SECURITY_GATE_REPORT.md
docs/SECURITY_RELEASE_CHECKLIST.md
docs/SECURITY_REMEDIATION_TRACKER.md
docs/SECURITY_TEST_PLAN.md
docs/SECURITY_THREAT_MODEL.md
docs/SOFTWARE_BILL_OF_MATERIALS.md
docs/VULNERABILITY_ASSESSMENT.md
pdcm/app.py
pdcm/engines/cleaner_engine.py
pdcm/engines/duplicate_engine.py
pdcm/services/path_policy.py
pdcm/services/quarantine.py
pdcm/services/quarantine_store.py
pdcm/services/scan_control.py
pdcm/services/scan_history.py
pdcm/services/system_info.py
pdcm/ui/cleaner_dashboard.py
pdcm/ui/dashboard.py
pyproject.toml
requirements.in
requirements.lock
tests/conftest.py
tests/test_cleaner_engine.py
tests/test_cleaner_ui.py
tests/test_duplicate_engine.py
tests/test_path_policy.py
tests/test_quarantine.py
```

`.idea/`, `.venv/`, `security-reports/`, build outputs and generated source ZIPs are local-only and excluded by `.gitignore`. The current worktree documentation has no machine-specific user paths, but the reachable baseline commit `7f30f8d` still contains one personal Windows user path in `docs/IMPLEMENTATION_PROGRESS.md`. Because that commit is an ancestor of the proposed publication, do not push this history until the owner authorizes a history-cleaning approach; no history rewrite or push was performed. A static scan of 53 publication-candidate worktree files and 37 reachable Git blobs found no high-confidence private-key, GitHub-token, AWS-access-key or Google-API-key patterns; this does not prove that all secrets or personal data are absent.

## Evidence limitations

- No hosted workflow URL or artifact is available; GitHub reports zero workflows and zero runs.
- Six link tests remain environment-blocked locally and were not counted as passing.
- VA-002 is an independent source-level finding, not a reproduced exploit.
- Current local scanner and Qt inventory outputs are retained under ignored `security-reports/` as `pip-audit-installed-current.json`, `pip-audit-lock-current.json`, `bandit-current.json` and `qt-wheel-inventory.txt`; these machine-local reports are not part of the publication allowlist.
- Dependency scanner zero-results are not proof of no vulnerabilities; broad advisory and reachability review remains incomplete.
- Installed PySide6 files are not a built installer. The final shipping file set and complete license/notice package remain unknown.
- No production-readiness or vulnerability-free claim is made.
