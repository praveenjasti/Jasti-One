# Jasti Cleaner manual regression checklist

Use the installed application without elevation. These checks are analysis-only:
do not approve file moves, restore files, or delete anything from the folders
being reviewed. The real-folder counts below are user-provided reference points,
not fixed pass/fail thresholds; Windows, installed software, and file contents
can change them.

## Launch and controls

- [ ] Start Jasti One with `.\.venv\Scripts\jasti-one.exe`.
- [ ] Confirm the app opens without administrator elevation.
- [ ] Visit every Jasti Cleaner tab, then return to Storage.
- [ ] Choose a synthetic folder, cancel the picker once, then choose it again.
- [ ] Run Analyze and confirm progress/status updates, results, and history.
- [ ] Start a synthetic scan and cancel it; confirm partial results are not shown.
- [ ] Switch to a different synthetic folder after a scan; confirm old results clear.
- [ ] Use filename search, size/age/type/extension filters, table-header sorting,
  and folder-grouped ordering on Large & old files.
- [ ] Change pages in Duplicates, Downloads, and Review; confirm counts and
  selected checkboxes persist when returning to a page.
- [ ] Select one member of a duplicate group, then try selecting every member;
  confirm the UI leaves at least one copy unselected.
- [ ] Refresh restore points for a synthetic folder; confirm this only reads
  operation records.
- [ ] Confirm Quarantine and Restore remain disabled on every visit.

## Reference folder: `D:\Songs`

- [ ] Select `D:\Songs` explicitly and run an analysis.
- [ ] Compare the measured files, folders, logical size, and exact duplicate
  groups with the latest known result (433 files, about 2.3 GB, 81 folders).
- [ ] Confirm the five intentionally created duplicate groups are still found
  by SHA-256, including copies with different names and locations.
- [ ] Check that the approximately 45.4 MB duplicate-byte estimate is shown as
  potential only; no copy is selected automatically.
- [ ] Confirm Temporary, Browser cache, and Developer caches explain that
  `D:\Songs` is outside their recognized locations rather than showing an
  unexplained empty table.
- [ ] Confirm older music files are not recommended for cleaning based only on
  age or size.
- [ ] Compare file contents, names, and modification times before and after;
  analysis must not change them.

## Reference folder: `C:\Users\jasti\Downloads`

- [ ] Select the Downloads folder explicitly and run an analysis.
- [ ] Compare results with the latest known reference (451 files, about
  908.5 MB, 81 duplicate groups, and about 873.8 MB potential duplicate bytes).
- [ ] Confirm JDK, .NET, and Node.js installers are visible and described as
  review items, not assumed disposable.
- [ ] Confirm archives, disk images, old downloads, and recognized partial
  download suffixes have contextual guidance.
- [ ] Search for a filename and filter by extension, age, size, and file type.
- [ ] Confirm every duplicate group retains at least one unselected copy and
  potential bytes are not described as guaranteed free space.
- [ ] Confirm browser privacy information remains visible and no cookies,
  passwords, history, autofill, or payment data are shown.

## Isolated synthetic locations

For category checks, use a throwaway profile layout rather than the actual
Windows profile or real package caches. In a PowerShell session, set
`$testHome` to a new directory under `$env:TEMP`, then set `USERPROFILE`,
`LOCALAPPDATA`, `APPDATA`, `TEMP`, and `TMP` to corresponding paths under that
directory before launching Jasti One. Keep `SystemRoot` and other system
variables unchanged.

- [ ] Create a `Temp` folder with a small `.tmp` file and select that folder.
  Confirm the file is labeled for careful review and its active/locked state is
  explicitly not tested.
- [ ] Create `.m2\repository` and `AppData\Local\npm-cache` with small synthetic
  files. Select those folders and confirm the Maven and npm cache descriptions
  distinguish reusable caches from source/build output.
- [ ] Create a synthetic `Downloads` folder with text fixtures named
  `sample.exe`, `archive.zip`, `disk.iso`, `old.txt`, and `partial.crdownload`.
  Confirm the names/extensions produce contextual guidance only; the `.exe`
  fixture is text and must not be executed.
- [ ] Put two identical small files with different names in the synthetic
  scope; confirm exact duplicate detection and no automatic selection.
- [ ] Close the app and remove only the explicitly created synthetic test
  directory using its verified full path.

## Evidence to record

- [ ] Windows version, Python version, PySide6 version, and whether the app was
  launched from an installed environment or the source checkout.
- [ ] Scan counts, elapsed time, inaccessible/changed count, duplicate groups,
  and potential duplicate bytes.
- [ ] Any control that did not respond, including the active tab and the
  expected versus observed result.
- [ ] Confirm no test selected a personal folder other than the two explicitly
  authorized reference folders and no file was moved or deleted.
