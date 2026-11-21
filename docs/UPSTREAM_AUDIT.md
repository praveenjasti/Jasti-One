# Jasti One — Upstream audit status

The detailed first-pass assessment is maintained in [`OPEN_SOURCE_ASSESSMENT.md`](OPEN_SOURCE_ASSESSMENT.md).

## Current status
- No upstream source code has been vendored.
- Exact duplicate engine now uses an independently implemented two-stage fingerprint + full SHA-256 pipeline.
- All cleanup/mutation functionality remains subject to explicit approval and recovery design.
- PC Cleaner, SafeDuplicateFinder, Sift and StorageSaver are candidates for deeper review, not approved dependencies.

## Important
A README/landing-page review is not a complete source-code, security, dependency or legal audit. Pin commits and inspect all mutation paths before adopting upstream code.
