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

import sys

from lib.manifest import verify_manifest


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
