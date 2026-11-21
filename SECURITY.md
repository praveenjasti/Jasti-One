# Security Policy

## Supported versions

Security fixes apply to the current `main` branch and the latest published release. Older releases are unsupported unless a release exception is explicitly documented.

## Reporting vulnerabilities

Do not open a public issue for an unresolved vulnerability.

Use GitHub's **Report a vulnerability** private reporting feature for this repository:

1. Confirm private vulnerability reporting is enabled in the repository settings.
2. If the feature is not available, contact the maintainer through an already-established private channel before sharing technical details.
3. Do not open a public issue or post reproduction details for an unresolved vulnerability.

Include in a private report:

1. Affected component and version.
2. Reproduction steps using isolated test data.
3. Impact and whether exploitation was confirmed.
4. Do not access or modify another user's data.
5. Allow reasonable time for triage and remediation before disclosure.

If the maintainers are not responsive, document the disclosure attempt in the private record. Once remediation is available, publish the affected versions, fixed version, and mitigation.

## Security review gates

Every development milestone must include:

- A threat-model update for new trust boundaries or privileged operations.
- A manual code review for path handling, deletion, authentication, network, OAuth, logs and AI tool calls.
- Security regression tests using synthetic and isolated data.
- Dependency, licence and SBOM review.
- A CVE/advisory assessment with confirmation that a clean scan is not a security clearance.
- Release-blocking resolution or an approved, time-bound exception.
