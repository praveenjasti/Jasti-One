# Jasti One Security Remediation Tracker

| Finding | Owner | Severity | Target | Status | Verification | Blocker |
|---|---|---|---|---|---|---|
| VA-001 Scan-root/reparse-point and file-change controls | Engineering | High | Cleaner MVP | Windows handle-based controls reviewed; open until symlink-capable hosted Windows tests run. Root `Path.resolve()` report was corrected: Windows returns before the non-Windows resolve branch | Windows 11 / Python 3.13.17: 59 passed, 0 failed, 6 skipped. Strict retry: 6 failed during symlink creation with WinError 1314. Junction and post-handle rename tests passed locally | Yes |
| VA-002 Quarantine/restore safety | Engineering | Medium | Controlled cleanup | Open: independent review found a source-parent replacement race that can move a pinned source outside the selected root between path validation and handle rename. Destination-parent and concurrent-operation mitigations remain. Same-volume only; service/UI operations default off; no permanent deletion | Source-level finding (8/10 confidence); not reproduced at runtime. Local suite: 59 passed, 6 symlink skips; no hosted Windows run | Yes |
| VA-003 Gmail secure OAuth | Security + Engineering | High | Gmail MVP | Not started | Token/log tests | Yes |
| VA-004 AI permission enforcement | Security + Engineering | High | AI MVP | Not started | Prompt/command tests | Yes |
| VA-005 Dependency advisories and SAST | Engineering | Unknown | Every build | pip-audit and Bandit rerun in this gate review with no findings. Targeted NVD/GHSA/OSV/vendor checks resolve the known lxml advisories at 6.1.3; broad all-package coverage remains open | Current installed pip-audit: 84 records/0 findings; lock pip-audit: 81 records/0 findings; Bandit: 0 findings/3,618 LOC; JSON reports remain local in ignored `security-reports/` | Yes, until broader review |
| VA-006 Signed updater | Engineering/Release | High | Release 1 | Not started | Artifact verification | Yes |
| Licence evidence and SBOM | Legal/Security/Engineering | High | Before commercial release | In progress | Signed release checklist | Yes |
| VA-007 Full resolved dependency graph and hashes | Engineering | Medium | Before MVP release | Python 3.13 lock implemented and hash-validated; verify target platforms/build artifacts before release | `requirements.lock`: 80 exact pins/1,059 SHA-256 hashes; clean install, editable install, `pip check`, and hash dry-run passed | Yes, until release-platform review |
| VA-008 Browser profile privacy boundary | Engineering | High if regressed | Cleaner MVP | Cache-only metadata classification and complete browser-profile duplicate exclusion implemented | Synthetic Edge-profile test passes; verifies Cookies, History, Login Data and Web Data are not inventoried or hashed | Independent review required |
| CAR-001 pytest tmpdir advisory | Engineering | Moderate | CI tooling | Historical 8.0.0 pin replaced by 9.0.3; final lock and installed pip-audit scans found no known vulnerability | `pip-audit-lock-final.json`, `pip-audit-installed-final.json`; local full test suite passed except six symlink-permission skips | No; recheck on updates |
| VA-009 Manifest authenticity | Security + Engineering | Medium | Before enabling quarantine/restore | Confirmed residual: same-user writable manifest and payload are not authenticated. DPAPI CurrentUser/same-user HMAC are not boundaries against malicious code running as that user | Independent review (9/10 confidence); no MAC/key service/separate-principal authority implemented | Yes |
| Hosted CI evidence | Engineering | High | Before release gate closure | Workflow prepared for `windows-2025`, strict symlink mode, privilege evidence and complete artifact retention; remote remains public and has 0 workflows/0 runs. No push performed | GitHub Actions API reports no hosted run or artifact | Yes |
| Licence evidence / SBOM | Legal + Security + Engineering | High | Before commercial release | CycloneDX generated and validated; 83 components/84 dependency entries. Installed Qt wheel metadata and native payload inventoried. Version-matched Chromium/Qt third-party notices, exact final bundle, unknown metadata and legal compatibility approval remain open | Metadata CSV: 81/83 components have license metadata; protobuf and uritemplate unknown. Actual wheel contents contain a commercial-license reference, not a complete open-source/third-party notice bundle | Yes |

## Milestone process

At the start of every milestone:

1. Add or update the affected threat-model entries.
2. Assign owners and target releases to findings.
3. Identify trust-boundary and unsafe-operation changes.
4. Add focused tests before enabling the feature.

At milestone completion:

1. Run the pull-request security workflow.
2. Complete manual code review of every privileged or destructive path.
3. Triage dependency CVEs by reachability and affected package version.
4. Review licences and assets in the dependency or source change.
5. Close findings only with evidence.
6. Record approved exceptions with owner, justification and expiry.
