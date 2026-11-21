# Jasti One Licence Compatibility Assessment

**Status:** Blocked pending actual license/NOTICE and packaging review; legal approval required before commercial distribution

## Distribution model
Commercial, proprietary Jasti One application distributed with third-party binaries and libraries. Exact source disclosure, copyleft and notice requirements depend on the final dependency and linking choices.

## Compatibility matrix
| Licence | Jasti One suitability | Condition |
|---|---|---|
| MIT | Generally suitable | Preserve copyright and licence notice |
| Apache-2.0 | Generally suitable | Preserve notices and patent notice; review NOTICE |
| BSD-2/BSD-3 | Generally suitable | Preserve notices |
| LGPL | Conditional | Preserve library boundaries and source/licence rights; final legal review |
| GPL | Conditional/likely incompatible for copied or linked proprietary components | Isolate or obtain separate rights |
| AGPL | High risk | Prohibit integration unless network-use disclosure strategy is approved |
| Unknown/missing | Not approved | Replace or obtain written permission |

## Current gate
No upstream source is copied. The installed PySide6 6.12.0 metadata reports `LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only`; the installed PySide6_Essentials, PySide6_Addons, PySide6_Pdf 6.12.0.140, PySide6_WebEngine 6.12.0.140 and shiboken6 metadata reports the same expression. Qt for Python documents LGPL and commercial licensing and notes that some Qt modules are GPL-only. The Qt Company states that LGPL distribution requires, among other items, corresponding library source or an offer, replacement/relinking rights and required installation information, notices and licence text; its list is not exhaustive. These terms have not been assessed against Jasti One's eventual Windows packaging method. Do not assume the desktop application's source may remain closed without satisfying all LGPL conditions.

The `PySide6==6.12.0` pin resolves on the tested Python 3.13 environment. Its wheel metadata requires PySide6_Essentials, PySide6_Addons, PySide6_WebEngine and PySide6_Pdf. Each of the six installed Qt distributions (including shiboken6) reports `LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only`; each contains only a 470-byte `LicenseRef-Qt-Commercial.txt` among files named as license/notice, with SHA-256 `4f54763ac0fe2abd8f7f8d8fe370a94a08ebf84786aa0b91045bd6628deb08a3`. This is a commercial-license reference, not a complete open-source license text or third-party notice bundle. No separate Qt `LICENSE`/`NOTICE` files were found in the installed package trees. The inspection used unpacked installed wheel contents; raw wheel archives were not separately retained.

The installed tree includes `Qt6WebEngineCore.dll`, `QtWebEngineProcess.exe`, WebEngine `.pak` resources, and Qt PDF DLLs. Qt's official [WebEngine licensing page](https://doc.qt.io/qt-6/qtwebengine-licensing.html) explains that Chromium is incorporated into Qt WebEngine Core and lists the separate third-party license set. The project currently declares the PySide6 metapackage but imports neither WebEngine nor PDF; no bundler/installer configuration exists, so the exact redistributable contents are undetermined. The full packaged Qt and Chromium notice/source obligations must be resolved against version-matched vendor documents before release.

CycloneDX reports 83 components/84 dependency entries and the companion license inventory has metadata for 81 components; `protobuf==7.36.2` and `uritemplate==4.2.0` are unknown in the SBOM. The inventory is [`security-reports/dependency-licenses.csv`](../security-reports/dependency-licenses.csv); it does not replace inspecting package license files. Installed metadata's possible license expression is not a compliance determination. Some GPL-only Qt functionality may be incompatible with proprietary distribution unless separately licensed.

Before commercial release:

- Capture and review actual wheel licence texts and Qt component `LICENSES`/`NOTICE` files.
- Inventory all Qt runtime libraries, plugins, fonts, icons and other bundled assets.
- Decide between a verified LGPL-compliant distribution and a commercial Qt licence.
- Confirm relinking/replacement, corresponding-source delivery or written offer, prominent notices, patent obligations and distribution-channel compatibility with legal counsel.
- Keep any unknown or GPL-only component blocked until approval.

Sources: [Qt for Python licences](https://doc.qt.io/qtforpython-6/licenses.html), [Qt LGPL/GPL obligations](https://www.qt.io/development/open-source-lgpl-obligations), and [PySide6 6.12.0](https://pypi.org/project/PySide6/6.12.0/).
