#!/usr/bin/env python3
"""Verify that a manifest file matches the contents of its corresponding zip file.

Checks performed:
- Every zip entry appears in the manifest and vice versa
- Directory entries match
- For regular files: sha2, compression type, data offset, compressed size
- For RPA files: top-level sha2/compression/offset/compressed_size,
  plus each sub-entry sha2/offset/size within the decompressed RPA stream
- Raw (gap) sub-entries are verified by content
"""

import base64
import json
import sys
import zipfile

from lib.rpa import RpaReader
from lib.utils import COMPRESSION_NAMES, hash_sha2, get_zip_entry_offset


def verify_manifest(manifest_path):
    """Verify a manifest against its corresponding zip file.

    Returns:
        (errors, warnings) - lists of error/warning message strings.
    """
    with open(manifest_path, 'r', encoding='utf-8') as f:
        manifest_data = json.load(f)

    zip_path = manifest_path
    if zip_path.endswith('.manifest'):
        zip_path = zip_path[:-len('.manifest')]

    errors = []
    warnings = []

    try:
        zf = zipfile.ZipFile(zip_path, 'r')
    except FileNotFoundError:
        errors.append(f"Zip file not found: {zip_path}")
        return errors, warnings
    except zipfile.BadZipFile:
        errors.append(f"Not a valid zip file: {zip_path}")
        return errors, warnings

    raw_zip = open(zip_path, 'rb')

    # Build sets of names for cross-checking
    zip_names = {info.filename for info in zf.infolist()}
    manifest_names = set(manifest_data.keys())

    for name in manifest_names - zip_names:
        errors.append(f"In manifest but not in zip: {name}")
    for name in zip_names - manifest_names:
        errors.append(f"In zip but not in manifest: {name}")

    # Verify each entry present in both
    for info in zf.infolist():
        name = info.filename
        if name not in manifest_data:
            continue  # already reported above

        props = manifest_data[name]

        if info.is_dir():
            if not props.get('directory'):
                errors.append(f"{name}: zip entry is a directory but manifest does not mark it as such")
            continue

        if props.get('directory'):
            errors.append(f"{name}: manifest marks as directory but zip entry is a file")
            continue

        # --- Compression ---
        expected_compression = props.get('compression')
        if info.compress_type not in COMPRESSION_NAMES:
            errors.append(f"{name}: unknown compression type {info.compress_type}")
        elif COMPRESSION_NAMES[info.compress_type] != expected_compression:
            errors.append(f"{name}: compression mismatch: "
                          f"zip={COMPRESSION_NAMES[info.compress_type]}, manifest={expected_compression}")

        # --- Offset ---
        actual_offset = get_zip_entry_offset(raw_zip, info)
        expected_offset = props.get('offset')
        if expected_offset is not None and actual_offset != expected_offset:
            errors.append(f"{name}: offset mismatch: zip={actual_offset}, manifest={expected_offset}")

        # --- Compressed size ---
        expected_csize = props.get('compressed_size')
        if expected_csize is not None and info.compress_size != expected_csize:
            errors.append(f"{name}: compressed_size mismatch: "
                          f"zip={info.compress_size}, manifest={expected_csize}")

        # --- SHA2 of decompressed content ---
        expected_sha2 = props.get('sha2')
        if expected_sha2 is not None:
            actual_sha2 = hash_sha2(zf.open(info))
            if actual_sha2 != expected_sha2:
                errors.append(f"{name}: sha2 mismatch: zip={actual_sha2}, manifest={expected_sha2}")

        # --- RPA sub-entries ---
        rpa_entries = props.get('rpa') or props.get('blob')
        if rpa_entries is not None:
            verify_rpa_entries(zf, name, rpa_entries, errors)

    raw_zip.close()
    zf.close()
    return errors, warnings


def verify_rpa_entries(zf, zip_entry_name, rpa_entries, errors):
    """Verify RPA/blob sub-entries against the decompressed RPA stream."""
    try:
        rpa_stream = zf.open(zip_entry_name)
    except Exception as e:
        errors.append(f"{zip_entry_name}: cannot open for RPA verification: {e}")
        return

    for i, entry in enumerate(rpa_entries):
        if 'raw' in entry:
            # Raw gap: verify content matches
            expected_bytes = base64.b64decode(entry['raw'])
            offset = entry.get('offset')
            if offset is not None:
                rpa_stream.seek(offset)
                actual_bytes = rpa_stream.read(len(expected_bytes))
            else:
                # Raw entries without explicit offset are sequential —
                # we can't easily verify position, just check length is sane
                actual_bytes = rpa_stream.read(len(expected_bytes))
            if actual_bytes != expected_bytes:
                errors.append(f"{zip_entry_name}: rpa entry {i}: raw content mismatch "
                              f"(expected {len(expected_bytes)} bytes)")
        elif 'sha2' in entry:
            entry_offset = entry.get('offset')
            entry_size = entry.get('size')
            if entry_offset is None or entry_size is None:
                errors.append(f"{zip_entry_name}: rpa entry {i}: missing offset or size")
                continue
            rpa_stream.seek(entry_offset)
            actual_sha2 = hash_sha2(rpa_stream, entry_size)
            if actual_sha2 != entry['sha2']:
                errors.append(f"{zip_entry_name}: rpa entry {i}: sha2 mismatch: "
                              f"actual={actual_sha2}, manifest={entry['sha2']}")
        else:
            errors.append(f"{zip_entry_name}: rpa entry {i}: unrecognized entry (no raw or sha2)")

    rpa_stream.close()


def main():
    if len(sys.argv) < 2:
        print("Usage: renpy-creator-verify-manifest.py <manifest> [<manifest2> ...]")
        sys.exit(1)

    all_ok = True
    for manifest_path in sys.argv[1:]:
        print(f"Verifying {manifest_path} ...")
        errors, warnings = verify_manifest(manifest_path)

        for w in warnings:
            print(f"  WARNING: {w}")
        for e in errors:
            print(f"  ERROR: {e}")

        if errors:
            print(f"  FAILED ({len(errors)} errors, {len(warnings)} warnings)")
            all_ok = False
        else:
            print(f"  OK ({len(warnings)} warnings)")

    sys.exit(0 if all_ok else 1)


if __name__ == '__main__':
    main()
