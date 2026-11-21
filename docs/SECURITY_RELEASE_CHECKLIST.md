# Jasti One Security Release Checklist

All boxes are required for a production release.

## Vulnerability and dependencies
- [ ] No unresolved Critical or exploitable High finding.
- [ ] Medium findings have approved, time-bound exceptions or mitigation.
- [x] Python 3.13 locked and installed dependency graphs scanned with pip-audit; zero known vulnerabilities reported.
- [ ] NVD, GHSA, OSV and vendor advisories checked for affected entries.
- [ ] Fixed versions or documented mitigations are recorded.
- [ ] Dependabot alerts reviewed.

## Supply chain and build
- [x] Python 3.13 dependency lock and package hashes verified (80 pins, 1,059 SHA-256 hashes).
- [ ] Full transitive dependency lock is generated and validated for every release platform; current evidence covers tested Python 3.13 environment.
- [ ] Package sources trusted.
- [x] CycloneDX SBOM generated and schema-validated for the locked development/optional environment; production artifact SBOM remains required.
- [x] pip-audit and Bandit executed with zero reported findings for the tested environment/source.
- [ ] Build is reproducible and artifacts are signed.
- [ ] Artifact hashes and signatures are published.

## Licences
- [ ] Every dependency and upstream licence/NOTICE file is captured and reviewed; metadata inventory exists but two entries are unknown.
- [ ] Version and commit SHA are pinned.
- [ ] Attribution and NOTICE obligations are satisfied.
- [ ] Qt/native asset/licence obligations are complete; the installed dependency closure includes WebEngine/Chromium and PDF modules, but the final bundled file set and required notices are not yet established.
- [ ] Compatibility assessment approved.

## Runtime protection
- [ ] Least privilege and workspace allowlists verified.
- [ ] Destructive operations require explicit approval.
- [ ] Quarantine and restore receive independent release approval; service and UI gates remain disabled.
- [ ] OAuth tokens use secure storage and logs are redacted.
- [ ] Local endpoints authenticate and rate-limit.
- [ ] AI tools require approval and cannot bypass application permissions.

## Release record
- [ ] Private vulnerability reporting channel is enabled and monitored.
- [ ] Branch protection requires review from configured CODEOWNERS.
- Release: __________
- Security approver: __________
- Date: __________
- Exceptions: link to approved, justified, time-bound records.

## Current blockers (21 November 2026)
- VA-001 remains open: six symlink tests could not create links locally (`WinError 1314`); strict mode failed explicitly. Hosted Windows workflow has not run.
- VA-002 remains open: source parent directories are not pinned through the quarantine move, so a timed parent rename can take the still-pinned file outside the selected root. VA-009 also remains open: a same-user writer can forge a manifest/payload pair.
- The configured public, empty GitHub remote reports zero workflows and zero runs. No source was pushed; public publication requires owner authorization.
- Full NVD/GHSA/vendor-by-vendor review, final Qt bundle/notice reconciliation and commercial license approval remain incomplete.
