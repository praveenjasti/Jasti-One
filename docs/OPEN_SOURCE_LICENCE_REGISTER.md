# Jasti One Open-source Licence Register

**Status:** Preliminary PyPI metadata checked for direct packages; licence texts/assets and complete transitive inventory not verified

| Component/repository | Exact version/commit | Licence reported | Licence file | Provenance | Obligations | Status |
|---|---|---|---|---|---|---|
| Jasti One | Repository HEAD | Proprietary project code unless a separate licence is declared | None | This repository | Review before distribution | Needs approval |
| PySide6 6.7.0 | Package release | `LGPL` (PyPI metadata); Qt for Python lists LGPL/GPL/commercial terms | Wheel licence texts not captured | [PyPI](https://pypi.org/project/PySide6/6.7.0/); [Qt licensing](https://doc.qt.io/qtforpython-6/licenses.html) | Determine selected Qt modules and LGPL/GPL/commercial option; dynamic relinking, source/offer, notices and packaging obligations | Blocked; legal review required |
| PySide6-Essentials 6.7.0 | Package release | `LGPL` (PyPI metadata) | Wheel licence texts not captured | PyPI/Qt distribution | Inventory bundled Qt libraries and applicable notices/relocation obligations | Needs investigation |
| PySide6-Addons 6.7.0 | Package release | `LGPL` (PyPI metadata) | Wheel licence texts not captured | PyPI/Qt distribution | Inventory bundled Qt modules, plugins and notices; identify GPL-only modules | Needs investigation |
| shiboken6 6.7.0 | Package release | `LGPL` (PyPI metadata) | Wheel licence texts not captured | PyPI/Qt distribution | Review bindings/generator distribution terms and notices | Needs investigation |
| psutil 5.9.8 | Package release | BSD-3-Clause (PyPI metadata) | Licence text not captured | PyPI | Preserve copyright and licence notice | Needs investigation |
| google-api-python-client 2.120.0 | Package release | Apache 2.0 (PyPI metadata) | Licence/NOTICE not captured | PyPI | Preserve notices and patent terms | Needs investigation |
| google-auth-oauthlib 1.2.0 | Package release | Apache 2.0 (PyPI metadata) | Licence/NOTICE not captured | PyPI | Preserve notices and patent terms | Needs investigation |
| pytest 9.0.3 | Package release | MIT (PyPI metadata) | Licence text not captured | PyPI | Preserve copyright and licence notice | Development-only |
| pip-audit 2.7.3 | Package release | Apache (PyPI classifier) | Licence text not captured | PyPI | Verify exact licence and notices | Development-only |
| bandit 1.7.8 | Package release | Apache-2.0 (PyPI metadata) | Licence text not captured | PyPI | Preserve notices and patent terms | Development-only |
| cyclonedx-bom 4.3.0 | Package release | Apache-2.0 (PyPI metadata) | Licence text not captured | PyPI | Preserve notices and patent terms | Development-only |
| setuptools build requirement | Version range `>=69` | MIT (PyPI classifier; exact resolved version unknown) | Licence text not captured | PyPI | Pin build dependency and preserve notice | Needs investigation |
| Qt for Python bundled third-party code/assets | Included components not yet determined | Component-specific (Qt docs list third-party licences) | Not inventoried from selected wheels | Qt for Python docs | Check only components actually redistributed; preserve each notice; separately review fonts/icons/assets | Blocked by package-content inventory |
| Transitive Python packages | Unresolved | Unknown | Not captured | PyPI/native wheels | Generate complete dependency graph; inspect each package and native asset | Blocked by missing resolved environment |
| PC Cleaner | Unpinned | Apache-2.0 reported | Must capture exact LICENSE | GitHub | Attribution, notice, patent clauses | Candidate only |
| SafeDuplicateFinder | Unpinned | MIT reported | Must capture exact LICENSE | GitHub | Attribution/copyright | Candidate only |
| Sift | Unpinned | MIT application; excluded font reported | Must capture LICENSE and asset terms | GitHub | Attribution; font separately | Candidate only |
| StorageSaver | Unpinned | MIT reported | Must capture exact LICENSE | GitHub | Attribution/copyright | Candidate only |
| libimobiledevice | Unpinned | LGPL reported | Must capture full package files | External upstream | Linking/source obligations | Research only |

No source from candidate repositories is imported. Direct-package PyPI licence metadata was checked, but packaged licence texts, native contents, all transitives and candidate repository licence files are not verified. Capture exact package files/metadata and transitive licences before distribution. Bundled fonts, icons and images require separate review.
