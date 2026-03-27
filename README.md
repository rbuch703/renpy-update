An Update Package Generator for Ren'Py-Based Visual Novels
===

Tired of transferring gigabytes of data for a new version of a Ren'Py - based game when the new version actually adds only 10% of new content? This is the tool for you!

This tool creates update packages that allow *updating* one version of a Ren'Py - based game to a new version. The update packages contain only the differences betwen versions, so they are much smaller and thus faster and cheaper to transfer than the full archive.

Update packages can be expected to be
- a few *dozen* megabytes in size for bug fix updates
- a few *hundred* megabytes in size for content updates

Usage
===

Content Creator: Create the Update Package
---

Execute `./renpy-creator-build-update-package --source <source_zip_archive> --dest <dest_zip_archive>` to create the update package `update.zip` that can update `<source_zip_archive>` to `<dest_zip_archive>`. This `<update.zip>` file can be arbitrarily renamed afterwards. Then, make that update package available to your users while indicating which base game version it applies to.

The parameters `--source` and `--dest` can be used multiple times, in which case this tool will create a single update package that allow each of the destination archives to be recreated from any one of the source archives. This allows for more versatile update packages like

1. a single update package that can be used to update both, the Windows and Linux versions of a Ren'Py game (though ideally you'd have a single `<dest_zip_archive>` that contains both, a Windows and Linux version to begin with)
2. a single update package that can be used to update any 0.13 `alpha`, `beta`, `release` or `bugfix` version of your game to the most recent 0.14 version
3. a single update package that can be used to update any previous 0.14 version of your game (`alpha`, `beta`, and any patch level) to the most recent 0.14 version.

### Efficiency
The tool operates on individual game assets, no matter if they exist as individual files or are packaged in an `.rpa` archive. Any asset that's in both versions of the game (source and destination) won't be stored in the update package, even if its file location changes between the game versions.

However, the tool recognized assets only by their hashes. So any tiny modification of a game asset (recompression, modifying resolution, modifying metadata) will make the new asset version distinct from the old one, and thus requires including the asset into the update package.


Gamer: Update Your game to a Newer Version
---

In a single folder, collect

1. the `renpy-update.py` script from this repository
2. the update package (e.g. `update.zip`) the content creator has provided
3. one of the old game versions the update package applies to, either as the original .zip file or its uncompressed contents

(So, the simplest approach is to copy `renpy-update.py` and `update.zip` into your game folder).

Then, execute `python3 renpy-update.py update.zip` in that folder (this currently requires that you have [Python 3](https://www.python.org/downloads/) installed on your computer). This will
1. display which old game versions the update package is compatible with.
2. scan whether the contents in your current folder are compatible with the update package.
3. prompt you for which new game version you want to update to (usually, there will only be exactly one version), and create that version.

This will leave you with a `.zip` file for the new game version that can be used in the same way as the full game download.

By default, the created new game archive is an uncompressed `.zip` file in order to speed up archive generation. If you want a smaller archive, you can pass `--compress` to `renpy-update.py` to enable compression at the cost of longer processing times (usually 1-5 minutes, depending on your computer and the game size).

Note that the new game *archive* created by `renpy-update.py` won't be bit-for-bit identical to the one the content creator may have provided as an alternative download, so any hash-based validation of the file itself will fail. This is by design. However, its *contents are* bit-for-bit identical with the contents of the original archive, so, any hash-based validation of the *extracted* .zip file contents should succeed.