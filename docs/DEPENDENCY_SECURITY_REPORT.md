# Jasti One Dependency Security Report

**Status:** Workflow configured; no successful scan evidence yet

## Direct dependencies
| Package | Configured version | Purpose | Evidence |
|---|---|---|---|
| PySide6 | 6.7.0 | Windows desktop UI | pip-audit |
| psutil | 5.9.8 | Local system inventory | pip-audit |
| google-api-python-client | 2.120.0 | Gmail API | Optional Gmail extra |
| google-auth-oauthlib | 1.2.0 | Gmail OAuth | Optional Gmail extra |
| pytest | 9.0.3 | Tests | Development only; updated after OSV/GHSA finding for 8.0.0 |
| pip-audit | 2.7.3 | Python advisory scan | Development CI |
| bandit | 1.7.8 | Python SAST | Development CI |
| cyclonedx-bom | 4.3.0 | CycloneDX SBOM | Development CI |

## Controls and limitations
- `pyproject.toml` has exact pins for direct runtime and optional/dev dependencies.
- `requirements.in` is only a provisional direct-dependency input; it is **not** a lockfile and has no transitive pins or hashes.
- A separate CI lock-integrity job fails closed until `requirements.lock` exists and passes pip's `--require-hashes` dry-run.
- Weekly Dependabot updates.
- PR, push, and weekly workflow configuration exists; no successful hosted run has been verified.
- The workflow is configured for pip-audit against the installed CI environment and requirements input, Bandit, pytest and CycloneDX.
- Package source, hashes and resolved transitive versions remain unreviewed.
- Local tool installation failed because Windows Application Control blocked Python's `pyexpat` DLL; only pip is installed in the selected environment.

Tool selection prioritizes coverage and low maintenance: pip-audit for Python advisories, Bandit for Python SAST, CycloneDX for SBOM. CodeQL workflow configuration exists but has not run. The SCA/SAST tool configuration is not evidence that the source or dependencies passed.
