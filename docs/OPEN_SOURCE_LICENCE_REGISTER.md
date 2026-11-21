# Jasti One Open-source Licence Register

**Status:** Python 3.13 SBOM metadata and installed Qt distribution contents inventoried; full transitive license, final bundle and legal review remain open
**Assessment date:** 21 November 2026

## Current Python dependency inventory

The generated CycloneDX SBOM contains 83 components and 84 dependency entries from the locked Python 3.13 development/optional environment. [`security-reports/dependency-licenses.csv`](../security-reports/dependency-licenses.csv) lists every SBOM component with its exact installed version, package URL, and license metadata when available. 81/83 components have metadata; `protobuf==7.36.2` and `uritemplate==4.2.0` are marked `UNKNOWN`. The full package/version/hash resolution is in [`requirements.lock`](../requirements.lock).

This is an inventory of installed metadata, not a complete upstream `LICENSE`/`NOTICE` capture for all 83 components, a repository-commit source audit, or a final-installer manifest. `protobuf==7.36.2` and `uritemplate==4.2.0` have `UNKNOWN` license metadata in the generated SBOM; preserve those unknowns until exact upstream files are independently verified.

## High-impact licence review

| Component | Exact locked version | Metadata licence | Distribution concern | Status |
|---|---:|---|---|---|
| PySide6 | 6.12.0 | `LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only` | Its wheel metadata requires Essentials, Addons, WebEngine and PDF distributions. The installed tree contains QtWebEngine/Chromium and PDF native payload; exact installer bundle and licensing path require approval | Legal review required |
| PySide6_Essentials | 6.12.0 | Same Qt alternative expression | Native Qt Core/Gui/Widgets and other Essentials libraries are present in the installed environment | Legal review required |
| PySide6_Addons | 6.12.0 | Same Qt alternative expression | Installed dependency closure includes add-on modules; identify actual app-used and redistributed modules | Legal review required |
| PySide6_Pdf | 6.12.0.140 | Same Qt alternative expression | `PySide6` wheel metadata requires this package; Qt PDF native libraries are installed. Final bundle inclusion is not verified | Legal review required |
| PySide6_WebEngine | 6.12.0.140 | Same Qt alternative expression | `PySide6` wheel metadata requires this package; Chromium is incorporated in Qt WebEngine Core. Third-party notices and final bundle inclusion require review | Legal review required |
| shiboken6 | 6.12.0 | Same Qt alternative expression | Installed binding/runtime package; review corresponding notices and licensing path | Legal review required |
| protobuf | 7.36.2 | Unknown in installed metadata | Obtain and inspect exact upstream license and notices | Blocked |
| uritemplate | 4.2.0 | Unknown in installed metadata | Obtain and inspect exact upstream license and notices | Blocked |
| Remaining Python dependencies | Exact versions in lock and CSV | See CSV | Verify actual license files, notices, provenance and any vendored/native assets | Not yet individually reviewed |
| Jasti One | Repository baseline/current tree | No project license declared here | Establish proprietary/open-source distribution terms before shipping | Owner decision required |

### Qt wheel and native-payload evidence

The installed PySide6 6.12.0, PySide6_Addons 6.12.0, PySide6_Essentials 6.12.0, PySide6_Pdf 6.12.0.140, PySide6_WebEngine 6.12.0.140 and shiboken6 6.12.0 distribution metadata each declares `LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only`. Each distribution contains only `LicenseRef-Qt-Commercial.txt` among files named as a license/notice: 470 bytes, SHA-256 `4f54763ac0fe2abd8f7f8d8fe370a94a08ebf84786aa0b91045bd6628deb08a3`. It states that valid commercial Qt licensees may use the software under their written agreement. The scanned installed package trees contained no separate Qt `LICENSE`, `NOTICE`, `COPYING` or third-party-notice files. The commercial reference is not an LGPL/GPL license text and is not evidence that Jasti One has a Qt commercial license. This inventory covers the unpacked installed wheel contents and distribution metadata; raw wheel archives were not separately retained.

The installed PySide6 package tree contains 3,893 files: 349 DLLs, 61 `.pyd` extensions and 18 executables, including `Qt6WebEngineCore.dll`, `QtWebEngineProcess.exe`, WebEngine resource `.pak` files, and `Qt6Pdf.dll` / `Qt6PdfQuick.dll` / `Qt6PdfWidgets.dll`. The `pyproject.toml` directly depends on `PySide6==6.12.0`; its wheel metadata requires Essentials, Addons, WebEngine and PDF distributions. Application source search found no WebEngine or PDF imports. No installer/bundler configuration or generated installer exists, so this is the resolved Python installation payload, not a verified list of files in a distributable.

Qt's official [Qt for Python licensing page](https://doc.qt.io/qtforpython-6/licenses.html) points users to third-party license notices. The official [Qt WebEngine licensing page](https://doc.qt.io/qt-6/qtwebengine-licensing.html) states that Qt WebEngine incorporates Chromium in Qt WebEngine Core and lists a substantial third-party license set. The wheel's commercial-reference file is not that full third-party attribution set. Before shipping WebEngine, obtain the version-matched notices/source materials required by the selected Qt license and reconcile them with the exact packaged modules. The Qt Company [LGPL/GPL obligations](https://www.qt.io/development/open-source-lgpl-obligations) describe source/relinking, notice and other conditions; legal counsel must determine whether the chosen packaging/distribution model complies.

Qt metadata is a choice of possible licensing regimes, not evidence that Jasti One has selected or complied with one. Do not distribute until legal review selects the applicable license path and the actual packaged Qt modules/notices are reconciled.

## Other assets and sources

- Candidate Cleaner repositories are not vendored into Jasti One; their README license statements are not reuse approval.
- iOS starter code, fonts, icons, images, documentation and any future third-party assets require independent provenance and license records.
- Upstream package commit SHAs are not represented by wheel version/hash metadata; do not claim a commit-level source audit from this inventory.

## Commercial release gate

Commercial release remains blocked until all unknown metadata is resolved, actual license/NOTICE files and native/assets are reviewed, required attribution/source/redistribution terms are satisfied, Qt licensing is approved, and an authorized reviewer approves the compatibility assessment. The metadata inventory alone does not establish that all licenses are compatible.
