# Jasti One Dependency Security Report

**Status:** Python 3.13 hash lock, pip-audit and Bandit executed; no production-readiness claim
**Assessment date:** 21 November 2026

## Resolved dependency set

- `requirements.in` supplies the direct runtime, optional Gmail, development and pinned build-backend inputs.
- `requirements.lock` resolves **80 exact package versions** with **1,059 SHA-256 hashes**. It includes `setuptools==84.2.1`, required for the editable package installation.
- The lock is generated for Python 3.13 and verified on Windows 11 with CPython 3.13.17. It includes the optional Gmail and development packages, so it is broader than a minimal runtime distribution.
- A hash-required install in the clean Python 3.13 environment passed; `pip install --no-deps --no-build-isolation -e .` passed; `pip check` returned `No broken requirements found.`; a subsequent `pip install --dry-run --require-hashes -r requirements.lock` passed.

## Direct pins

| Package | Version | Purpose |
|---|---:|---|
| PySide6 | 6.12.0 | Desktop UI |
| psutil | 7.2.2 | Local system inventory |
| google-api-python-client | 2.120.0 | Optional Gmail API |
| google-auth-oauthlib | 1.2.0 | Optional Gmail OAuth |
| pytest | 9.0.3 | Tests |
| pip-audit | 2.10.1 | Dependency advisory scan |
| bandit | 1.9.4 | Python SAST |
| cyclonedx-bom | 9.0.0 | CycloneDX SBOM |
| setuptools | 84.2.1 | Pinned build backend |

All transitive package names and exact versions are in [`../requirements.lock`](../requirements.lock). The resulting installed graph also includes the editable Jasti One project.

## Executed security tools

| Command | Result | Saved evidence |
|---|---|---|
| `python -m pip_audit --local --format json -o security-reports/pip-audit-installed-current.json` | Re-run in this gate review: Exit 0; 84 dependency records; 0 vulnerabilities | Current installed-environment JSON |
| `python -m pip_audit -r requirements.lock --format json -o security-reports/pip-audit-lock-current.json` | Re-run in this gate review: Exit 0; 81 dependency records; 0 vulnerabilities | Current lockfile JSON |
| `python -m bandit -q -r pdcm -f json -o security-reports/bandit-current.json` | Re-run in this gate review: Exit 0; 0 findings; 3,618 LOC; 0 skipped tests | Current Bandit JSON |
| CycloneDX environment generation | Exit 0; SBOM schema validation passed; 83 components and 84 dependency entries | `security-reports/sbom-locked-environment.cdx.json` |
| License metadata extraction from SBOM | 81/83 components have license metadata; protobuf 7.36.2 and uritemplate 4.2.0 are unknown | `security-reports/dependency-licenses.csv` |

The initial lock scan recorded `lxml==5.4.0` as affected by `CVE-2026-41066`, `GHSA-vfmq-68hx-4jfw`, and `PYSEC-2026-87` (High; fixed in 6.1.0). Current lock resolves `lxml==6.1.3`; NVD 2.0 API, GHSA and OSV all confirm the 6.1.0 fix threshold. The vendor also marks LP#2165901 (a separate lxml 6.1.2 parameter-entity issue) fixed in 6.1.3. Current pip-audit runs returned no known vulnerabilities. See the [CVE and Advisory Register](CVE_AND_ADVISORY_REGISTER.md).

## Limitations and remaining work

- pip-audit and Bandit results are evidence from the exact tested Python 3.13 environment; they do not prove the application secure or establish complete coverage of NVD, GitHub advisories, official vendor advisories, reachability, native Qt binaries, or future disclosures.
- The SBOM describes the locked development/optional environment, not a signed production installer. It passed CycloneDX 1.6 JSON schema validation. Its license fields are package metadata and may be absent or imprecise; the CSV is an inventory aid, not legal approval.
- GitHub Actions is configured but has not run: the configured remote repository currently reports zero workflows and zero workflow runs. No hosted results or artifacts are claimed.
- Review package provenance, registry trust, native Qt contents, exact notices/license texts, bundled assets, and the final distribution image before commercial release.
- Continue PR and scheduled scans, and review alerts against NVD, GHSA, OSV and vendor sources. A clean scan is not a security guarantee.
