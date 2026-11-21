# Jasti One Security Remediation Tracker

| Finding | Owner | Severity | Target | Status | Verification | Blocker |
|---|---|---|---|---|---|---|
| VA-001 Scan-root/reparse-point and file-change controls | Engineering | High | Cleaner MVP | Partial; residual Windows traversal race and junction validation | Synthetic exact-duplicate/file-change smoke passed; symlink creation unavailable; pytest/junction pending | Yes |
| VA-002 Quarantine/restore safety | Engineering | High | Cleanup MVP | Blocked by implementation | Restore test suite | Yes |
| VA-003 Gmail secure OAuth | Security + Engineering | High | Gmail MVP | Not started | Token/log tests | Yes |
| VA-004 AI permission enforcement | Security + Engineering | High | AI MVP | Not started | Prompt/command tests | Yes |
| VA-005 Dependency advisories and complete lock | Engineering | Unknown | Every build | Blocked; tools unavailable locally, direct-only input is not a lock | No scan evidence | Yes |
| VA-006 Signed updater | Engineering/Release | High | Release 1 | Not started | Artifact verification | Yes |
| Licence evidence and SBOM | Legal/Security/Engineering | High | Before commercial release | In progress | Signed release checklist | Yes |
| VA-007 Full resolved dependency graph and hashes | Engineering | High | Before MVP release | Not implemented | Complete lock and SBOM required | Yes |
| CAR-001 pytest tmpdir advisory | Engineering | Moderate | Next CI run | Configured fix 9.0.3; re-scan/test pending | CI evidence required; not a product runtime dependency | Yes until verified |

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
