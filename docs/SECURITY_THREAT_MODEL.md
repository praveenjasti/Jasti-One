# Jasti One Security Threat Model

**Status:** Evidence update — not a security clearance
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
| TM-001 | Path traversal/arbitrary access | Treat the user-selected scan root as the scope boundary; reject protected roots and verify Windows root components using held handles | Before scans |
| TM-002 | Symlink/junction attacks | Reject reparse points in the selected root, prune linked entries, verify file identity around reads | Before scans |
| TM-003 | Unsafe deletion/overwrite | Keep quarantine and restore disabled until the security gate is cleared; when enabled, require explicit review, same-volume no-replace moves, strict manifest/hash/identity checks and no-overwrite restore; no permanent deletion | Before release |
| TM-004 | OAuth token disclosure | OS secure store; no tokens in Git/logs; least scopes | Before Gmail |
| TM-005 | AI prompt injection | Untrusted-content boundary; approval for shell, deletion, network and transfers | Before AI tools |
| TM-006 | Malicious or malformed/tampered manifests | Strict versioned schema, duplicate/unknown-field rejection, in-root paths, payload identity/hash checks, no-overwrite restore and durable states; explicitly account for unauthenticated same-user modification | Before release |
| TM-007 | Local IPC compromise | Loopback binding, authentication, allowlist, rate limiting | Before Wi-Fi/local API |
| TM-008 | Dependency/supply-chain attack | Lockfiles, hashes, advisories, SBOM, trusted registries | Every build |
| TM-009 | Insecure updater | Signed immutable releases, TLS, downgrade protection | Before updater |
| TM-010 | Sensitive log leakage | Structured redaction, no tokens or file contents in logs | Continuous |
| TM-011 | Browser-profile privacy exposure | Restrict inspection to recognized cache subdirectories; exclude Cookies, History, Login Data and Web Data from inventory and duplicate hashing | Before browser-cache analysis |
| TM-012 | AI/untrusted filename rendering | Treat file names and paths as untrusted display data; never execute discovered files or commands | Every local scan |
| TM-013 | Quarantine source/destination race or cross-volume interruption | Hold validated source and destination parent handles without delete sharing across no-replace rename; serialize operations; same-volume only; reject cross-volume movement; reconcile durable states | Before enabling quarantine |

## Residual risks
Quarantine and restore code is present but disabled in both the UI and service by default. Local Windows/Python 3.13.17 tests passed for destination-handle replacement cases and synthetic quarantine/restore operations. Independent source review confirms destination-parent and concurrent-operation mitigations, but found a separate VA-002 source-scope race: `_open_move_file` checks the opened file's final path, while nested source-parent handles are not held through the later handle rename. A same-user process able to rename a parent between validation and move can move the pinned source outside the selected root. No runtime race test or eligible hosted Windows execution has verified this case. A same-user process with write access to the store can also coherently rewrite an unauthenticated manifest and payload; schema or hash checks do not establish provenance. DPAPI `CurrentUser` or a same-user HMAC would protect key material from other accounts/at-rest inspection but would not stop code running as that same user from using the key. ACLs do not defend against the owner, an administrator or same-user code; local logs in the same trust boundary are also mutable. No MAC, signature, protected key service or append-only audit boundary is implemented.

The full local suite reports 59 passed, 0 failed and 6 skipped; each skip is a symbolic-link creation failure with `WinError 1314`. A strict run of those six tests failed at link creation with the same error, proving the local permission limitation rather than passing link behavior. Junction tests ran locally. The CI workflow now targets `windows-2025`, records `whoami /priv`, and retains the complete security report directory, but GitHub currently reports zero workflows and zero runs; hosted verification is unavailable. The selected root is per scan, not an application-wide workspace allowlist; directory enumeration uses `os.scandir` while validated handles are held rather than native handle-relative enumeration. No production-readiness or vulnerability-free claim is made.
