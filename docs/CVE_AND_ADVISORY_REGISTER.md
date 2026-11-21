# Jasti One CVE and Advisory Register

**Status:** Direct OSV queries recorded; no complete dependency scan; evidence collection still blocked
**Review date:** 21 November 2026

| ID | Package | Used version | CVE/GHSA | CVSS | Severity | Reachable? | Classification | Fixed version | Mitigation | Source | Verification | Release |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| CAR-001 | pytest (development/CI) | 8.0.0 (previous configured pin) | CVE-2025-71176 / GHSA-6w46-j5rx-g56g | CVSS 3.1 vector `AV:L/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L`; numeric score not confirmed | Moderate (GitHub Advisory) | Used by Ubuntu CI test step; vulnerable tmpdir behavior is Unix-specific. Product runtime does not depend on pytest. Exploitability in isolated hosted runner not established | Potential vulnerability | 9.0.3 | Updated configured dev pin; re-scan and test required | [GHSA](https://github.com/advisories/GHSA-6w46-j5rx-g56g), [OSV](https://osv.dev/vulnerability/GHSA-6w46-j5rx-g56g), [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-71176) | OSV exact-version query and GitHub advisory verified; fix not installed or re-scanned | CI tooling |
| CAR-002 | Other configured packages | PySide6/PySide6-Essentials/PySide6-Addons/shiboken6 6.7.0; psutil 5.9.8; google-api-python-client 2.120.0; google-auth-oauthlib 1.2.0; pip-audit 2.7.3; bandit 1.7.8; cyclonedx-bom 4.3.0; pytest 9.0.3 | No records returned by exact OSV queries for these versions | N/A | Not determined | Not determined | Needs investigation | Not determined | Complete installed-environment scan and NVD/GHSA/vendor review still required | OSV exact package/version queries | Direct package query only; transitive graph not scanned; former google-api and CycloneDX pins were invalid and corrected | Every build |
| CAR-003 | Transitive dependencies | Not resolved | Not assessed | Not assessed | Unknown | Not assessed | Needs investigation | Not assessed | Generate and scan actual resolved graph | PyPI metadata and advisory sources | No complete lock or SBOM | Every build |

## Required register workflow
1. Generate the complete environment and a full transitive lockfile with hashes.
2. Scan with pip-audit on every pull request and weekly.
3. Confirm exact package/version and transitive path.
4. Check NVD, GHSA, OSV and the package vendor.
5. Determine application reachability.
6. Record fixed versions and owner-approved exceptions.

The installed environment contained only pip. The individual OSV queries do not cover transitive packages or establish that a component is safe. No vulnerability-free claim is made. Current rows record configured direct versions, not a resolved dependency inventory.
