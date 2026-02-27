#!/usr/bin/env python3

"""Optimize a Ren'Py zip file so that it can serve/double as a differential update package.

The only optimization performed is to store .rpa files without compression, so that the files
they contain can be referenced as individual byte ranges into the zip file.
"""

import sys
import zipfile

def main():
    if len(sys.argv) != 3:
        print("Usage: renpy-optimize-zip.py <input.zip> <output.zip>")
        sys.exit(1)

    input_zip_path = sys.argv[1]
    output_zip_path = sys.argv[2]

    with zipfile.ZipFile(input_zip_path, 'r') as input_zip:
        with zipfile.ZipFile(output_zip_path, 'w') as output_zip:
            for info in input_zip.infolist():
                data = input_zip.read(info.filename)

                # Create new ZipInfo to control compression
                new_info = zipfile.ZipInfo(info.filename)
                new_info.date_time = info.date_time
                new_info.external_attr = info.external_attr

                # Set executable bit for .sh files (Unix permissions: 0755)
                if info.filename.endswith('.sh'):
                    new_info.external_attr = 0o755 << 16

                # Use STORED (no compression) for .rpa files, otherwise preserve original
                if info.filename.endswith('.rpa'):
                    new_info.compress_type = zipfile.ZIP_STORED
                else:
                    new_info.compress_type = info.compress_type

                output_zip.writestr(new_info, data)

    print(f"Created {output_zip_path} with .rpa files stored without compression")


if __name__ == '__main__':
    main()
