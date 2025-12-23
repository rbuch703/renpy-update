#! /usr/bin/python3

import hashlib
import json
import sys
import zipfile

from lib.rpa import RpaReader



def main():
    if len(sys.argv) != 2:
        print("Usage: renpy-create-update-package.py <output_package.zip>")
        sys.exit(1)
    
    output_package_path = sys.argv[1]
    files = {}
    directories = set()

    with zipfile.ZipFile(output_package_path, 'r') as zf:
        print(f"Parsing zip file `{output_package_path}`")
        for info in zf.infolist():
            if info.is_dir():
                assert info.filename not in files, "Duplicate file in package!"
                directories.add(info.filename)
            else:
                file_contents = zf.read(info)
                sha2 = hashlib.sha256(file_contents).hexdigest()
                assert info.filename not in files, "Duplicate file in package!"

                if info.filename.endswith('.rpa'):
                    print(f"  Parsing RPA file `{info.filename}`")
                    reader = RpaReader(zf.open(info))
                    key, contents = reader.content_map()
                    assert key != "sha2"
                    files[info.filename] = {
                        "sha2": sha2,
                        key: contents
                    }
                else:
                    files[info.filename] = {"sha2": sha2}





    json.dump({"directories": list(directories), "files": files}, open("package.json", "w"), indent=2)

if __name__ == '__main__':
    main()
