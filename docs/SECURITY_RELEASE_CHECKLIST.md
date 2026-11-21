# Jasti One Security Release Checklist

All boxes are required for a production release.

## Vulnerability and dependencies
- [ ] No unresolved Critical or exploitable High finding.
- [ ] Medium findings have approved, time-bound exceptions or mitigation.
- [ ] Direct and transitive dependencies scanned.
- [ ] NVD, GHSA, OSV and vendor advisories checked for affected entries.
- [ ] Fixed versions or documented mitigations are recorded.
- [ ] Dependabot alerts reviewed.

## Supply chain and build
- [ ] Dependency lock and package hashes verified.
- [ ] Full transitive dependency lock is generated for the release platform; a direct requirements list is insufficient.
- [ ] Package sources trusted.
- [ ] CycloneDX SBOM generated and reviewed.
- [ ] pip-audit and Bandit pass or findings are explicitly accepted.
- [ ] Build is reproducible and artifacts are signed.
- [ ] Artifact hashes and signatures are published.

## Licences
- [ ] Every dependency and upstream licence file is captured.
- [ ] Version and commit SHA are pinned.
- [ ] Attribution and NOTICE obligations are satisfied.
- [ ] Qt/native asset/licence obligations are complete.
- [ ] Compatibility assessment approved.

## Runtime protection
- [ ] Least privilege and workspace allowlists verified.
- [ ] Destructive operations require explicit approval.
- [ ] Quarantine and restore safety tests pass.
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
