# Jasti One Software Bill of Materials

**Status:** CycloneDX generated and schema-validated for the locked Python 3.13 environment; not a production-release SBOM
**Assessment date:** 21 November 2026

## Evidence

- Input environment: clean Windows Python 3.13.17 environment, installed from `requirements.lock` with `--require-hashes`, followed by the editable Jasti One project.
- Generator: CycloneDX Python toolchain pinned in the lock (`cyclonedx-bom==9.0.0`).
- Output: [`security-reports/sbom-locked-environment.cdx.json`](../security-reports/sbom-locked-environment.cdx.json).
- Validation: CycloneDX 1.6 `JsonStrictValidator` passed.
- Contents: 83 components and 84 dependency entries. The SBOM includes optional Gmail and development packages in addition to the desktop dependencies.
- Preserved artifact SHA-256: `5A1D7DEB3FB1A2D1B0E290EADB71844BF27836BF09D8BC92E84DA77CC3C0C58F`. The corresponding `requirements.lock` SHA-256 is `64D52B0ACB5CD6A01AD17C7A231BE8706632F5FD08AF514950E589D05BCDF4D8`.
- Companion metadata inventory: [`security-reports/dependency-licenses.csv`](../security-reports/dependency-licenses.csv); 81 components carry license metadata, while protobuf 7.36.2 and uritemplate 4.2.0 are unknown in installed metadata.

The SBOM is generated from the installed environment and is not a signed build-artifact SBOM. Package hashes are pinned separately in `requirements.lock`; this output does not prove that the final installer contains only these components or that every bundled native file has been inventoried. The Windows application distribution, Qt plugins/Qt WebEngine contents, iOS dependencies, fonts, icons and other assets require separate inventories before distribution.

## Release requirements

- Generate a CycloneDX SBOM for the actual release build and reconcile every component with the lock, installer and artifact hashes.
- Investigate unknown or ambiguous license metadata and inspect exact package license/NOTICE files, Qt native modules, bundled assets and trademarks.
- Review provenance and trusted package sources; archive the SBOM and signed release manifest.
- Regenerate and review the SBOM after each dependency or packaging change.
