# Jasti One Licence Compatibility Assessment

**Status:** Blocked pending package evidence; legal review required before commercial distribution

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
No upstream source is copied. PyPI metadata for PySide6 6.7.0 reports `LGPL`; Qt for Python documents LGPL and commercial licensing and notes that some Qt modules are GPL-only. The Qt Company states that LGPL distribution requires, among other items, corresponding library source or an offer, replacement/relinking rights and required installation information, notices and licence text; its list is not exhaustive. These terms have not been assessed against Jasti One's eventual Windows packaging method. Do not assume the desktop application's source may remain closed without satisfying all LGPL conditions.

The resolved package set, exact wheel contents, selected Qt modules, plugin loading, bundler output and all license files have not been reviewed. The PySide6 distribution pulls `PySide6-Essentials`, `PySide6-Addons` and `shiboken6` at the same version; all also report `LGPL` in PyPI metadata. Qt for Python's own third-party component notices must be checked against the modules/assets actually redistributed. Some GPL-only Qt functionality may be incompatible with proprietary distribution unless separately licensed.

Before commercial release:

- Capture and review actual wheel licence texts and Qt component `LICENSES`/`NOTICE` files.
- Inventory all Qt runtime libraries, plugins, fonts, icons and other bundled assets.
- Decide between a verified LGPL-compliant distribution and a commercial Qt licence.
- Confirm relinking/replacement, corresponding-source delivery or written offer, prominent notices, patent obligations and distribution-channel compatibility with legal counsel.
- Keep any unknown or GPL-only component blocked until approval.

Sources: [Qt for Python licences](https://doc.qt.io/qtforpython-6/licenses.html), [Qt LGPL/GPL obligations](https://www.qt.io/development/open-source-lgpl-obligations), and PyPI metadata for [PySide6 6.7.0](https://pypi.org/project/PySide6/6.7.0/).
