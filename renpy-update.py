#!/usr/bin/env python3
"""Apply a Ren'Py update package to recreate a game archive."""

import base64
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import zipfile

from lib.manifest import extract_leaf_hashes
from lib.rpa import RpaReader
from lib.utils import COMPRESSION_NAMES, hash_sha2

# Reverse mapping: compression name -> zipfile constant
COMPRESSION_TYPES = {name: code for code, name in COMPRESSION_NAMES.items()}

# ANSI colors
YELLOW = '\033[33m'
GREEN  = '\033[32m'
RESET  = '\033[0m'

# Inserted between consecutive sha2 entries when reconstructing "rpa"-format content.
RPA_SPACER = b"Made with Ren'Py."


def main():
    compressed = '--compress' in sys.argv
    args = [a for a in sys.argv[1:] if a != '--compress']
    if len(args) != 1:
        print(f"Usage: {sys.argv[0]} [--compress] <update_package.zip>", file=sys.stderr)
        sys.exit(1)

    update_path = args[0]
    if not zipfile.is_zipfile(update_path):
        print(f"Error: not a valid zip file: {update_path}", file=sys.stderr)
        sys.exit(1)

    # Source blobs may reside within an .rpa archive which in turn resides within a source .zip.
    # It's complicated to read them directly from the .zip file while keeping memory consumption
    # low and speed high. So, instead we go for a simpler approach and write any matching .rpa
    # sub-entries to a common temporary zip file. This allows us to treat them mostly like regular
    # zip entries when reconstructing the output archive. This is a bit wasteful in terms of disk
    # space and time, but it keeps the code simpler and more robust.
    tmp_file = tempfile.TemporaryFile()
    # Use STORED mode for the temporary zip to avoid spending time compressing data we will just
    # read back later.
    tmp_zip = zipfile.ZipFile(tmp_file, 'w', compression=zipfile.ZIP_STORED)

    with zipfile.ZipFile(update_path, 'r') as update_zip:
        names = update_zip.namelist()

        # --- Load source list and dest manifests from the update package ---
        sources = _load_sources(names)
        dest_manifests = _load_dest_manifests(update_zip, names)
        if not dest_manifests:
            print("Error: no manifests found in update package", file=sys.stderr)
            sys.exit(1)

        print("This is an RenPy update package to create the following archive(s):")
        for mname in dest_manifests:
            print(f"  - {GREEN}{_archive_name(mname)}{RESET}")

        print()
        print("Required inputs are the contents of at least one of the following source zip files")
        print("(either as .zip files or as files in the current folder):")

        for s in sources:
            print(f"  - {YELLOW}{s}{RESET}")

        print("\nWill now scan for those contents:")
        print("1. in the update package itself")
        # Blobs available directly in the update package — verify each hash matches its name
        update_blobs = set()
        for n in names:
            if not n.startswith('blobs/') or len(n) <= len('blobs/'):
                continue
            expected_sha2 = n[len('blobs/'):]
            with update_zip.open(n) as stream:
                actual_sha2 = hash_sha2(stream)
            if actual_sha2 != expected_sha2:
                print(f"Error: blob {expected_sha2} has actual hash {actual_sha2}", file=sys.stderr)
                sys.exit(1)
            update_blobs.add(expected_sha2)

        # Required hashes per manifest and across all manifests
        manifest_required = {}
        all_required = set()
        rpa_whole_hashes = set()  # top-level sha2 of RPA entries (optional shortcuts)
        for mname, mdata in dest_manifests.items():
            hashes = set(extract_leaf_hashes(mdata))
            manifest_required[mname] = hashes
            all_required.update(hashes)
            for props in mdata.values():
                if 'rpa' in props and 'sha2' in props:
                    rpa_whole_hashes.add(props['sha2'])

        # --- Locate blob sources ---
        blob_locations = {}  # sha2 -> location descriptor
        # Search for both leaf hashes (required) and whole-RPA hashes (optional)
        search_hashes = all_required | rpa_whole_hashes
        remaining = set(search_hashes)

        # 1. Update package
        found = remaining & update_blobs
        for sha2 in found:
            blob_locations[sha2] = ('update',)
        remaining -= found

        # 2. Source zip files in current directory
        if remaining:
            print("2. in source zip files in the current directory:")
            _locate_in_source_zips(sources, remaining, blob_locations, tmp_zip)
            remaining = search_hashes - set(blob_locations)

        # 3. Recursively in the current directory (including RPAs)
        if remaining:
            print("3. recursively in the current directory (including RPAs):")
            _locate_on_disk(remaining, blob_locations, update_path, set(sources))
            remaining = search_hashes - set(blob_locations)

    tmp_zip.close()
    tmp_file.seek(0)
    tmp_zip = zipfile.ZipFile(tmp_file, 'r')

    # --- Report status per manifest ---
    print("\nManifest status:")
    recreatable = []
    for mname in sorted(dest_manifests):
        required = manifest_required[mname]
        missing = required - set(blob_locations)
        archive_name = _archive_name(mname)
        if missing:
            print(f"  {archive_name}: ❌ INCOMPLETE "
                  f"({len(missing)} of {len(required)} blobs missing)")
        else:
            print(f"  {archive_name}: ✅ COMPLETE")
            recreatable.append(mname)

    if not recreatable:
        print("\nError: no archives can be recreated.", file=sys.stderr)
        sys.exit(1)

    # --- Prompt user ---
    print("\nWhich archive would you like to recreate?")
    for i, mname in enumerate(recreatable, 1):
        print(f"  {i}. {GREEN}{_archive_name(mname)}{RESET}")
    print(f"  0. {YELLOW}Cancel{RESET}")
    while True:
        try:
            idx = int(input("Enter number: "))
            if idx == 0:
                print("Cancelled.")
                tmp_zip.close()
                tmp_file.close()
                sys.exit(0)
            if 1 <= idx <= len(recreatable):
                choice = recreatable[idx - 1]
                break
        except (ValueError, EOFError):
            pass
        print("Invalid choice, try again.")

    output_name = _archive_name(choice)
    if os.path.exists(output_name):
        print(f"\nError: {output_name} already exists.", file=sys.stderr)
        sys.exit(1)

    # --- Recreate the archive ---
    print(f"\nRecreating {output_name} ...")
    manifest_data = dest_manifests[choice]
    _recreate_archive(output_name, manifest_data, blob_locations, update_path, tmp_zip,
                       compressed)
    print(f"Done: {GREEN}{output_name}{RESET} ({os.path.getsize(output_name)} bytes)")

    tmp_zip.close()
    tmp_file.close()


# ---------------------------------------------------------------------------
# Helpers — loading update package metadata
# ---------------------------------------------------------------------------

def _load_sources(names):
    """Return list of source zip base-names from the sources/ folder."""
    sources = []
    for name in names:
        if name.startswith('sources/') and name != 'sources/':
            basename = os.path.basename(name)
            if basename.endswith('.manifest'):
                sources.append(basename[:-len('.manifest')])
    return sources


def _load_dest_manifests(update_zip, names):
    """Return dict of manifest_basename -> manifest_data from the manifests/ folder."""
    dest_manifests = {}
    for name in names:
        if name.startswith('manifests/') and name.endswith('.manifest'):
            data = json.loads(update_zip.read(name))
            dest_manifests[os.path.basename(name)] = data
    return dest_manifests


def _archive_name(manifest_name):
    """Derive the output archive filename from a manifest name."""
    if manifest_name.endswith('.manifest'):
        return manifest_name[:-len('.manifest')]
    return manifest_name


# ---------------------------------------------------------------------------
# Helpers — locating blobs
# ---------------------------------------------------------------------------

def _locate_in_source_zips(sources, remaining, blob_locations, tmp_zip):
    """Check source zip files in the current directory for needed blobs."""
    for source_name in sources:
        if not remaining:
            break
        if not os.path.exists(source_name) or not zipfile.is_zipfile(source_name):
            continue
        _scan_zip(source_name, remaining, blob_locations, tmp_zip)


def _scan_zip(zip_path, remaining, blob_locations, tmp_zip):
    """Scan a zip file for needed blobs, including inside RPA archives.

    Regular entries are recorded as ('zip_entry', ...).  RPA sub-entries that
    match are written to tmp_zip and recorded as ('tmp_zip', ...).
    """
    with zipfile.ZipFile(zip_path, 'r') as zf:
        for info in zf.infolist():
            if not remaining:
                break
            if info.is_dir():
                continue
            if info.filename.lower().endswith('.rpa'):
                _scan_rpa_in_zip(zf, zip_path, info, remaining, blob_locations, tmp_zip)
            else:
                with zf.open(info.filename) as stream:
                    sha2 = hash_sha2(stream)
                if sha2 in remaining:
                    blob_locations[sha2] = ('zip_entry', zip_path, info.filename)
                    remaining.discard(sha2)


def _scan_rpa_in_zip(zf, zip_path, info, remaining, blob_locations, tmp_zip):
    """Scan an RPA archive inside a zip for needed blobs."""
    rpa_data = zf.read(info.filename)

    # Check the whole-RPA hash (allows using the file verbatim)
    rpa_sha2 = hashlib.sha256(rpa_data).hexdigest()
    if rpa_sha2 in remaining:
        blob_locations[rpa_sha2] = ('zip_entry', zip_path, info.filename)
        remaining.discard(rpa_sha2)

    # Scan individual sub-entries
    try:
        rpa = RpaReader(io.BytesIO(rpa_data))
        for _name, (offset, size) in rpa.entries():
            if not remaining:
                break
            blob = rpa_data[offset:offset + size]
            sha2 = hashlib.sha256(blob).hexdigest()
            if sha2 in remaining:
                tmp_zip.writestr(sha2, blob)
                blob_locations[sha2] = ('tmp_zip', sha2)
                remaining.discard(sha2)
    except Exception: # pylint: disable=broad-except
        pass


def _locate_on_disk(remaining, blob_locations, update_path, source_names):
    """Recursively search the current directory for blobs."""
    abs_update = os.path.abspath(update_path)
    abs_sources = {os.path.abspath(s) for s in source_names}

    for root, _dirs, files in os.walk('.'):
        if not remaining:
            break
        for fname in files:
            if not remaining:
                break
            fpath = os.path.join(root, fname)
            abs_fpath = os.path.abspath(fpath)
            if abs_fpath == abs_update or abs_fpath in abs_sources:
                continue
            try:
                with open(fpath, 'rb') as f:
                    sha2 = hash_sha2(f)
                    if sha2 in remaining:
                        blob_locations[sha2] = ('file', fpath)
                        remaining.discard(sha2)
            except Exception: # pylint: disable=broad-except
                pass


# ---------------------------------------------------------------------------
# Reading a blob by its recorded location
# ---------------------------------------------------------------------------

def _read_blob(sha2, blob_locations, update_path, entry_name, out, zip_cache, tmp_zip):
    """Stream the raw bytes for a blob from its recorded source into out."""
    loc = blob_locations[sha2]
    kind = loc[0]

    if kind == 'tmp_zip':
        print(f"  {entry_name} <- tmp_zip:{sha2[:12]}...", file=sys.stderr)
        with tmp_zip.open(sha2) as src:
            shutil.copyfileobj(src, out)
        return

    if kind == 'update':
        print(f"  {entry_name} <- update package blobs/{sha2[:12]}...", file=sys.stderr)
        if update_path not in zip_cache:
            zip_cache[update_path] = zipfile.ZipFile(update_path, 'r')
        with zip_cache[update_path].open(f"blobs/{sha2}") as src:
            shutil.copyfileobj(src, out)
        return

    if kind == 'zip_entry':
        _, zip_path, zip_entry = loc
        print(f"  {entry_name} <- {zip_path}:{zip_entry}", file=sys.stderr)
        if zip_path not in zip_cache:
            zip_cache[zip_path] = zipfile.ZipFile(zip_path, 'r')
        with zip_cache[zip_path].open(zip_entry) as src:
            shutil.copyfileobj(src, out)
        return

    if kind == 'file':
        _, fpath = loc
        print(f"  {entry_name} <- {fpath}", file=sys.stderr)
        with open(fpath, 'rb') as src:
            shutil.copyfileobj(src, out)
        return

    if kind == 'rpa_file':
        _, fpath, offset, size = loc
        print(f"  {entry_name} <- {fpath}@{offset}+{size}", file=sys.stderr)
        with open(fpath, 'rb') as f:
            f.seek(offset)
            remaining = size
            while remaining > 0:
                chunk = f.read(min(1 << 20, remaining))
                if not chunk:
                    break
                out.write(chunk)
                remaining -= len(chunk)
        return

    raise ValueError(f"Unknown blob location type: {kind}")


# ---------------------------------------------------------------------------
# Archive reconstruction
# ---------------------------------------------------------------------------

def _recreate_archive(output_path, manifest_data, blob_locations, update_path, tmp_zip,
                      compressed):
    """Recreate a zip archive from a manifest and located blobs."""
    zip_cache = {}  # path -> open ZipFile (kept open to avoid re-parsing)
    try:
        with zipfile.ZipFile(output_path, 'w') as zout:
            for entry_name, props in manifest_data.items():
                if props.get('directory'):
                    zout.mkdir(entry_name)
                    continue

                if compressed:
                    compress_type = COMPRESSION_TYPES.get(
                        props.get('compression', 'STORED'), zipfile.ZIP_STORED)
                else:
                    compress_type = zipfile.ZIP_STORED
                info = zipfile.ZipInfo(entry_name)
                info.compress_type = compress_type
                if 'external_attr' in props:
                    info.external_attr = props['external_attr']

                with zout.open(info, 'w', force_zip64=True) as stream:
                    if 'rpa' in props and props.get('sha2') not in blob_locations:
                        # Reassemble from sub-entries (no whole-RPA blob available)
                        print(f"- Reconstructing RPA {entry_name} from "
                              f"{len(props['rpa'])} sub-entries ...")
                        _reconstruct_rpa(props['rpa'], blob_locations, update_path,
                                         entry_name, stream, zip_cache, tmp_zip)
                    else:
                        # Use the whole-file blob directly.  For 'rpa' entries this
                        # means the complete RPA was found verbatim; for regular and
                        # 'blob'-keyed entries this is the normal path.
                        sha2 = props['sha2']
                        _read_blob(sha2, blob_locations, update_path, entry_name,
                                   stream, zip_cache, tmp_zip)
    finally:
        for zf in zip_cache.values():
            zf.close()


def _reconstruct_rpa(rpa_entries, blob_locations, update_path, entry_name, stream,
                     zip_cache, tmp_zip):
    """Reconstruct an RPA file from entries in the simplified 'rpa' format.

    Layout: header(raw), entry1, spacer, entry2, spacer, ..., entryN, trailer(raw).
    Spacers between sha2 entries are implicit and re-inserted here.
    Writes each chunk directly to stream to avoid holding the whole RPA in memory.
    """
    sha2_count = 0

    for entry in rpa_entries:
        if 'raw' in entry:
            stream.write(base64.b64decode(entry['raw']))
        elif 'sha2' in entry:
            if sha2_count > 0:
                stream.write(RPA_SPACER)
            _read_blob(entry['sha2'], blob_locations, update_path, entry_name,
                       stream, zip_cache, tmp_zip)
            sha2_count += 1



if __name__ == '__main__':
    main()
