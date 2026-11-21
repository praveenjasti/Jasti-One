# Jasti One — Open-source assessment and integration decisions

**Assessment date:** 21 November 2026  
**Status:** First-pass desk audit. No third-party source code has been copied into this repository.

## Executive decision

Use open-source repositories as reference implementations and selective component candidates. Keep Jasti One's product architecture, permissions, risk model, UI and recovery lifecycle under our control.

### Priority decisions

| Area | Candidate | Decision | Why |
|---|---|---|---|
| Windows cleanup | [PC Cleaner](https://github.com/wiselead-oss/pc-cleaner) | **Study architecture; do not port wholesale yet** | Broad Windows cleanup, developer cache and startup management; .NET MAUI/C# architecture differs from our Python/PySide6 foundation. Its optional auto-clean path and permanent cache deletion are stricter than our desired default safety model. |
| Exact duplicates | [SafeDuplicateFinder](https://github.com/KOO-Kunner/SafeDuplicateFinder) | **Adopt algorithm ideas; rewrite and test in our engine** | MIT, standard-library-only Python, staged hashing, read-only scan, quarantine and restore. Small/young repository and manifest restore trust-boundary concerns mean no blind code copy. |
| iPhone media | [Sift](https://github.com/ModernAmusements/sift) | **High-priority iOS source audit** | MIT application code, native SwiftUI/PhotoKit/Vision, exact and similar media, contacts, Files picker, documented QA suite. Requires Xcode/macOS and real-device validation. |
| iPhone media | [StorageSaver](https://github.com/alidiab2/StorageSaver) | **Secondary algorithm/UX reference** | MIT, native SwiftUI, PhotoKit, Vision, AVFoundation and CryptoKit; exact duplicate SHA-256 and separate similar-media review lane. Public repository history is very small, so independently validate. |
| Gmail | [TrimBox](https://github.com/jayrdeaton/TrimBox) | **Further audit required** | Potential sender/unsubscribe workflow reference. Do not grant broad Gmail access until OAuth scopes, token handling and delete/archive paths are inspected. |
| USB connectivity | [libimobiledevice](https://github.com/libimobiledevice/libimobiledevice) | **Protocol research only** | Useful for supported device communication; does not grant unrestricted access to iOS app sandboxes. Review LGPL and all bundled component notices before distribution. |

## 1. SafeDuplicateFinder — code-level observations

Repository: https://github.com/KOO-Kunner/SafeDuplicateFinder  
Published licence: MIT. Main implementation: `safe_duplicate_finder.py`.

### Positive patterns worth retaining
- Read-only scan phase.
- Candidate reduction by file size, then first/last 64 KiB fingerprint, then full SHA-256.
- Skips symbolic links during traversal.
- Rechecks size and full digest before quarantine to detect stale scan results.
- Writes a JSON manifest after each move using a temporary file and atomic replace.
- Restore verifies file size and SHA-256 and refuses to overwrite an existing destination.

### Risks / changes required before any reuse
- The repository is very small (GitHub page showed one commit and no stars at assessment time); this is a maturity signal, not a code-quality verdict.
- The restore routine trusts absolute `original` and `quarantined` paths from `manifest.json`. It does not visibly constrain the quarantined source to the selected quarantine root or validate the original destination against the original scan root. Jasti One must validate both paths and manifest schema before restoring.
- Quarantine folder selection needs explicit policy: prevent scanning the quarantine folder itself and avoid unsafe source/destination overlap.
- A sorted path is not a meaningful “best copy” decision. Jasti One must not automatically choose a keeper based only on path order.
- Cross-volume `shutil.move` may become copy-then-remove. Jasti One should verify destination content before considering the source move complete, and record recovery state for interrupted operations.
- No upstream code is vendored in this release.

### Jasti One implementation decision
We independently implemented the staged candidate-filtering concept in `pdcm/engines/duplicate_engine.py`. The quick fingerprint is only a filter; full SHA-256 is still the final exact-match test. We also check file size and modification time before and after hashing. This is an independently written implementation, not copied source.

## 2. PC Cleaner — architecture reference

Repository: https://github.com/wiselead-oss/pc-cleaner  
Published licence: Apache-2.0.

### Worth studying
- Separation between core filesystem logic, presentation/view models and OS-specific platform services.
- Testable core logic.
- Category-based cleanup inventory.
- Startup manager and developer-cache discovery.
- Recycle Bin/Trash treatment for user files.

### Not adopting wholesale
- It is a .NET 10 / MAUI-oriented application, while the current Jasti One foundation is Python/PySide6. A full port would be a strategic rewrite, not a small component integration.
- Its documented optional “scan and auto clean” workflow is not our default. Jasti One requires item-level preview and explicit approval.
- Its documentation describes permanent deletion for regenerable caches. Jasti One should initially prefer reversible actions wherever practical and clearly label any irreversible cache operation.
- Do not run Docker, WSL, Git or package-manager cleanup commands without a separate, explicit developer-tools permission.

## 3. Sift — iPhone source audit candidate

Repository: https://github.com/ModernAmusements/sift  
Published licence: MIT (the README excludes its bundled brand font from the MIT grant).

### Worth studying
- PhotoKit and Vision integration.
- dHash + Vision feature prints for duplicate/similar media.
- Bounded background processing and cancellable scan pipeline.
- Explicit PhotoKit deletion confirmation and Recently Deleted explanation.
- Contacts duplicate detection and review.
- Native Files picker rather than pretending an app can scan all iOS files.
- QA document reports 40 unit tests and 9 UI tests passing on the stated simulator configuration in November 2026.

### Conditions before integration
- Inspect every PhotoKit mutation and Contacts merge path in source.
- Preserve Sift's attribution and separately review the bundled font/icon/brand assets; do not copy its branding into Jasti One.
- Re-run tests with our own fixtures and supported Xcode/iOS versions.
- Test on a physical iPhone, especially iCloud Photos and Contacts sync consequences.

## 4. StorageSaver — secondary iOS reference

Repository: https://github.com/alidiab2/StorageSaver  
Published licence: MIT.

Its README describes exact duplicate detection with SHA-256, a separate review lane for similar items, batch compression, and Apple's Photos confirmation flow. It says originals are only moved to Recently Deleted after a compressed replacement is reviewed and confirmed.

The public repository page showed only two commits at assessment time. Treat it as a focused reference, not a production-proven dependency.

## 5. Licensing and provenance gates

Before copying any code:
1. Pin an exact commit SHA, not a moving `main` branch.
2. Save the complete upstream licence and copyright notices.
3. Inventory transitive dependencies and their licences.
4. Record the exact files/functions copied or adapted.
5. Add required attribution and third-party notices.
6. Review trademark, icon, font, sample-data and documentation rights separately.
7. Run static analysis, dependency checks, tests and a manual security review.

MIT and Apache-2.0 are generally practical candidates, but the complete dependency and asset chain still needs review. LGPL/GPL/AGPL code requires a separate distribution and linking assessment. This document is an engineering assessment, not legal advice.

## 6. Next audit gates

- [ ] Pin commits and capture full licence files for PC Cleaner, SafeDuplicateFinder, Sift and StorageSaver.
- [ ] Review PC Cleaner Windows path discovery, deletion and startup registry operations.
- [ ] Review SafeDuplicateFinder quarantine/restore implementation and tests; add malicious-manifest tests to our own design.
- [ ] Review Sift PhotoKit deletion, Vision similarity thresholds, Contacts merge and Files picker source.
- [ ] Audit TrimBox Gmail scopes, OAuth implementation, token storage and mutation workflow.
- [ ] Produce a third-party notices and SBOM plan before shipping a distributable build.

## Sources reviewed

- PC Cleaner README/repository: https://github.com/wiselead-oss/pc-cleaner
- SafeDuplicateFinder README: https://github.com/KOO-Kunner/SafeDuplicateFinder
- SafeDuplicateFinder implementation: https://github.com/KOO-Kunner/SafeDuplicateFinder/blob/main/safe_duplicate_finder.py
- Sift README: https://github.com/ModernAmusements/sift
- Sift QA notes: https://github.com/ModernAmusements/sift/blob/main/docs/QA.md
- StorageSaver README: https://github.com/alidiab2/StorageSaver
