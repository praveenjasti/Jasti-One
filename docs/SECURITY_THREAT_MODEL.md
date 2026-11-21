# Jasti One Security Threat Model

**Status:** Initial implementation assessment — not a security clearance  
**Review date:** 21 November 2026

## Trust boundaries
- Desktop UI and local Python processes.
- Native iOS app, PhotoKit, Contacts and Files picker.
- Gmail OAuth and Google APIs.
- USB/Wi-Fi transfer services.
- AI prompt content and tool execution.
- Local database, files, manifests, quarantine and logs.
- Package registries, updater, installer and CI artifacts.

## Protected assets
- Personal files and metadata.
- OAuth access and refresh tokens.
- Local audit and quarantine manifests.
- Workspace integrity and deletion recovery.
- Credentials, signing keys and update keys.
- Third-party source and asset provenance.

## Mandatory threats and controls
| ID | Threat | Required control | Release target |
|---|---|---|---|
| TM-001 | Path traversal/arbitrary access | Treat the user-selected scan root as the scope boundary; canonicalize it and reject system roots | Before scans |
| TM-002 | Symlink/junction attacks | Reject reparse points in the selected root, prune linked entries, verify file identity around reads | Before scans |
| TM-003 | Unsafe deletion/overwrite | Preview; approval; reversible quarantine; refuse existing restore destination | Before cleanup |
| TM-004 | OAuth token disclosure | OS secure store; no tokens in Git/logs; least scopes | Before Gmail |
| TM-005 | AI prompt injection | Untrusted-content boundary; approval for shell, deletion, network and transfers | Before AI tools |
| TM-006 | Malicious or malformed manifests | Strict schema, canonical paths, hash verification, signed release metadata | Before restore |
| TM-007 | Local IPC compromise | Loopback binding, authentication, allowlist, rate limiting | Before Wi-Fi/local API |
| TM-008 | Dependency/supply-chain attack | Lockfiles, hashes, advisories, SBOM, trusted registries | Every build |
| TM-009 | Insecure updater | Signed immutable releases, TLS, downgrade protection | Before updater |
| TM-010 | Sensitive log leakage | Structured redaction, no tokens or file contents in logs | Continuous |

## Residual risks
No mutating cleanup, Gmail exchange, Wi-Fi transport or updater is production-enabled. The scanner remains read-only. Symlink creation was denied by the current Windows environment, so file/directory link rejection has not been runtime-verified; junction behavior and concurrent directory replacement during traversal also remain unverified. The selected root is per invocation, not an application-wide configured workspace allowlist. Expand this model after each feature lands.
