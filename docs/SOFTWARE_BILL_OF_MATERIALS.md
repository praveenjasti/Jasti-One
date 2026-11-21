# Jasti One Software Bill of Materials

**Status:** No SBOM generated; workflow configuration is not evidence

## Generation
The security workflow is configured to record `pip freeze` and create `sbom.cdx.json` with CycloneDX. No workflow run or artifact has been verified. The current workflow environment includes development and optional Gmail packages and must not be represented as the production release SBOM.

## Release requirements
- Generate CycloneDX JSON for the distributable environment.
- Include direct and transitive packages, versions, hashes where available, licences and provenance.
- Review native iOS third-party packages and assets separately.
- Compare the SBOM to the dependency snapshot and deployed artifact.
- Archive the SBOM and signed release manifest.
- Reassess SBOM entries after dependency updates and CVE notices.

## Components
`pyproject.toml` identifies configured direct requirements. `requirements.in` is a provisional direct-dependency input, not a complete resolved dependency inventory. Transitive packages, hashes, native Qt libraries, iOS components and bundled assets are not inventoried here.
