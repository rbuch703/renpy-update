#! /usr/bin/python3

import sys

from lib.manifest import generate_manifest, write_manifest


def main():
    if len(sys.argv) < 2:
        print("Usage: renpy-creator-create-manifest.py <package.zip> [<package2.zip> ...]")
        sys.exit(1)

    for zip_path in sys.argv[1:]:
        manifest_data = generate_manifest(zip_path)
        manifest_path = f"{zip_path}.manifest"
        write_manifest(manifest_data, manifest_path)
        print(f"  Wrote manifest `{manifest_path}`")

if __name__ == '__main__':
    main()
