#! /usr/bin/python3

import hashlib
import json
import sys
import zipfile

from lib.rpa import RpaReader
from lib.utils import COMPRESSION_NAMES, hash_sha2, get_zip_entry_offset


def main():
    if len(sys.argv) != 2:
        print("Usage: renpy-create-update-package.py <output_package.zip>")
        sys.exit(1)

    output_package_path = sys.argv[1]
    files = {}

    zf = zipfile.ZipFile(output_package_path, 'r')
    raw_zip = open(output_package_path, 'rb')
    print(f"Parsing zip file `{output_package_path}`")
    for info in zf.infolist():
        if info.is_dir():
            assert info.filename not in files, "Duplicate file in package!"
            files[info.filename] = {
                "directory" : True
            }
            pass
        else:
            sha2 = hash_sha2(zf.open(info))
            assert info.filename not in files, "Duplicate file in package!"
            assert info.compress_type in COMPRESSION_NAMES
            offset = get_zip_entry_offset(raw_zip, info)
            entry = {
                "sha2": sha2,
                "compression": COMPRESSION_NAMES[info.compress_type],
                "offset": offset,
                "compressed_size": info.compress_size,
            }

            if info.filename.endswith('.rpa'):
                print(f"  Parsing RPA file `{info.filename}`")
                reader = RpaReader(zf.open(info))
                # The raw data within the RPA only has an offset within the .zip file if it's
                # stored uncompressed within that .zip file.
                key, contents = reader.content_map( )
                assert key not in entry
                entry[key] = contents

            files[info.filename] = entry

    json.dump(files, open(f"{output_package_path}.manifest", "w"), indent=2)

if __name__ == '__main__':
    main()
