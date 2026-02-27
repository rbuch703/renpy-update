#!/usr/bin/env python3
import argparse
import hashlib
import os
import sys
import zipfile

from lib.manifest import (
    load_manifest,
    extract_leaf_hashes,
    extract_leaf_hash_names,
    extract_blob_from_manifest,
    manifest_zip_path,
)


def dump_largest_blob(label, hashes, manifest_paths):
    """Find the largest hash in `hashes`, extract it from the first matching manifest/zip, verify, and write to disk."""
    if not hashes:
        return
    largest_hash = max(hashes, key=hashes.get)
    largest_size = hashes[largest_hash]
    print(f"\nLargest {label}: {largest_hash} {largest_size}")

    data = None
    for manifest_path in manifest_paths:
        data = extract_blob_from_manifest(manifest_path, largest_hash)
        if data is not None:
            break

    if data is None:
        print(f"Error: could not find hash {largest_hash} in any manifest zip", file=sys.stderr)
        sys.exit(1)

    actual_hash = hashlib.sha256(data).hexdigest()
    if actual_hash != largest_hash:
        print(f"Error: extracted data hash mismatch: expected {largest_hash}, got {actual_hash}",
              file=sys.stderr)
        sys.exit(1)

    with open(largest_hash, 'wb') as f:
        f.write(data)
    print(f"Dumped to {largest_hash} ({len(data)} bytes)")


def process_sources(sources):
    """Generator function that yields tuples of (empty array, sha2 hash) for each source file."""
    for source in sources:
        if not os.path.exists(source):
            print(f"Warning: Source '{source}' does not exist", file=sys.stderr)
            continue

        if os.path.isdir(source):
            # Recursively process all files in the directory
            for root, _dirs, files in os.walk(source):
                for filename in files:
                    filepath = os.path.join(root, filename)
                    yield from process_file(filepath)
        elif os.path.isfile(source):
            if source.endswith('.zip'):
                # Process ZIP file contents
                try:
                    with zipfile.ZipFile(source, 'r') as zip_ref:
                        for zip_info in zip_ref.infolist():
                            if not zip_info.is_dir():
                                yield from process_zip_entry(zip_ref, zip_info)
                except zipfile.BadZipFile:
                    print(f"Warning: '{source}' is not a valid ZIP file", file=sys.stderr)
                except Exception as e:
                    print(f"Error processing ZIP file '{source}': {e}", file=sys.stderr)
            else:
                yield from process_file(source)
        else:
            print(f"Warning: Source '{source}' is not a regular file or directory", file=sys.stderr)

def process_file(filepath):
    """Process a single file and yield (empty array, sha2 hash)."""
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        file_hash = sha256_hash.hexdigest()
        yield ([], file_hash)
    except Exception as e:
        print(f"Error reading file '{filepath}': {e}", file=sys.stderr)

def process_zip_entry(zip_ref, zip_info):
    """Process a single entry from a ZIP file and yield (empty array, sha2 hash)."""
    sha256_hash = hashlib.sha256()
    try:
        with zip_ref.open(zip_info) as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        file_hash = sha256_hash.hexdigest()
        yield ([], file_hash)
    except Exception as e:
        print(f"Error reading ZIP entry '{zip_info.filename}': {e}", file=sys.stderr)

def main():
    parser = argparse.ArgumentParser(description='Process manifest and source files')
    parser.add_argument('--source', action='append',  required=True, help='Source manifest file, can be specified multiple times')
    parser.add_argument('--dest', action='append',  required=True, nargs='+', help='Destination manifest file(s) - can be specified multiple times')
    parser.add_argument('--verbose', action='store_true', help='Print detailed per-hash info for added and dropped entries')

    args = parser.parse_args()

    # --- 1. Source: intersection of leaf hashes across ALL source manifests ---
    source_hashes = None
    for manifest_path in args.source:
        leaf = extract_leaf_hashes(manifest_path)
        if source_hashes is None:
            source_hashes = dict(leaf)
        else:
            # Keep only hashes present in every source manifest
            source_hashes = {h: source_hashes[h] for h in source_hashes if h in leaf}
    if source_hashes is None:
        source_hashes = {}

    # --- 2. Dest: union of leaf hashes across ANY dest manifests ---
    dest_hashes = {}
    for dest_group in args.dest:
        for manifest_path in dest_group:
            leaf = extract_leaf_hashes(manifest_path)
            for h, size in leaf.items():
                if h in dest_hashes:
                    if dest_hashes[h] != size:
                        print(f"Error: hash {h} has conflicting sizes across dest manifests: "
                              f"{dest_hashes[h]} vs {size}", file=sys.stderr)
                        sys.exit(1)
                else:
                    dest_hashes[h] = size

    # --- 3. Diff: entries in dest but not in source ---
    diff_hashes = {h: size for h, size in dest_hashes.items() if h not in source_hashes}

    # --- 4. Dropped: entries in source but not in dest ---
    dropped_hashes = {h: size for h, size in source_hashes.items() if h not in dest_hashes}

    # --- Output ---
    for h, size in diff_hashes.items():
        print(f"{h} {size}")

    print()
    print(f"Source:  {len(source_hashes)} hashes, {sum(source_hashes.values())} bytes")
    print(f"- dropped: {len(dropped_hashes)} hashes, {sum(dropped_hashes.values())} bytes")
    print(f"Dest:    {len(dest_hashes)} hashes, {sum(dest_hashes.values())} bytes")
    print(f"- added:    {len(diff_hashes)} hashes, {sum(diff_hashes.values())} bytes")

    if args.verbose:
        # Build hash -> name mappings from the relevant manifests
        source_names = {}
        for manifest_path in args.source:
            source_names.update(extract_leaf_hash_names(manifest_path))

        dest_names = {}
        for dest_group in args.dest:
            for manifest_path in dest_group:
                dest_names.update(extract_leaf_hash_names(manifest_path))

        if dropped_hashes:
            print("\nDropped hashes:")
            for h, size in sorted(dropped_hashes.items(), key=lambda x: -x[1]):
                name = source_names.get(h, '(unknown)')
                print(f"  {h} {size:>12}  {name}")

        if diff_hashes:
            print("\nAdded hashes:")
            for h, size in sorted(diff_hashes.items(), key=lambda x: -x[1]):
                name = dest_names.get(h, '(unknown)')
                print(f"  {h} {size:>12}  {name}")

    # Flatten dest manifest paths for blob extraction
    dest_manifest_paths = [p for g in args.dest for p in g]

    # --- Build update zip containing all added blobs ---
    if diff_hashes:
        update_zip_path = "update.zip"
        print(f"\nBuilding {update_zip_path} with {len(diff_hashes)} entries ...")

        # --- 1. Build extraction plan from dest manifests ---
        # For each hash we need, record where to find it.
        # regular_plan: sha2 -> (manifest_path, zip_entry_name)
        # rpa_plan:     (manifest_path, zip_entry_name) -> {sha2: (offset, size), ...}
        #               plus metadata: compression, zip_data_offset
        remaining = set(diff_hashes.keys())
        regular_plan = {}       # sha2 -> (manifest_path, zip_entry_name)
        rpa_plan = {}           # (manifest_path, rpa_name) -> {"meta": {...}, "blobs": {sha2: (offset, size)}}

        for manifest_path in dest_manifest_paths:
            if not remaining:
                break
            manifest_data = load_manifest(manifest_path)
            for entry_name, props in manifest_data.items():
                if not remaining:
                    break
                if props.get('directory'):
                    continue
                if 'rpa' in props:
                    blobs_here = {}
                    for sub in props['rpa']:
                        if 'sha2' in sub and sub['sha2'] in remaining:
                            blobs_here[sub['sha2']] = (sub['offset'], sub['size'])
                            remaining.discard(sub['sha2'])
                    if blobs_here:
                        key = (manifest_path, entry_name)
                        rpa_plan[key] = {
                            "meta": {
                                "compression": props['compression'],
                                "zip_data_offset": props['offset'],
                            },
                            "blobs": blobs_here,
                        }
                else:
                    if 'sha2' in props and props['sha2'] in remaining:
                        regular_plan[props['sha2']] = (manifest_path, entry_name)
                        remaining.discard(props['sha2'])

        if remaining:
            print(f"Error: {len(remaining)} hashes not found in any dest manifest", file=sys.stderr)
            sys.exit(1)

        # --- 2. Extract and write ---
        written = 0
        total = len(diff_hashes)
        with zipfile.ZipFile(update_zip_path, 'w') as zout:
            # 2a. Regular files — one zip.read() each
            by_manifest = {}
            for sha2, (mpath, zname) in regular_plan.items():
                by_manifest.setdefault(mpath, []).append((sha2, zname))

            for mpath, entries in by_manifest.items():
                zip_path = manifest_zip_path(mpath)
                with zipfile.ZipFile(zip_path, 'r') as zf:
                    for sha2, zname in entries:
                        data = zf.read(zname)
                        _verify_and_write(zout, sha2, data)
                        written += 1
                        if written % 100 == 0:
                            print(f"  {written}/{total} entries written")

            # 2b. RPA files — one pass per RPA
            for (mpath, rpa_name), plan in rpa_plan.items():
                zip_path = manifest_zip_path(mpath)
                blobs = plan["blobs"]
                compression = plan["meta"]["compression"]
                zip_data_offset = plan["meta"]["zip_data_offset"]

                if compression == "STORED":
                    # Direct indexing into the raw zip file
                    print(f"  Extracting {len(blobs)} blobs from STORED RPA {rpa_name} (direct)")
                    with open(zip_path, 'rb') as raw:
                        for sha2, (rpa_offset, size) in blobs.items():
                            abs_offset = zip_data_offset + rpa_offset
                            raw.seek(abs_offset)
                            data = raw.read(size)
                            _verify_and_write(zout, sha2, data)
                            written += 1
                            if written % 100 == 0:
                                print(f"  {written}/{total} entries written")
                else:
                    # Compressed RPA — read decompressed stream once, sorted by offset
                    print(f"  Extracting {len(blobs)} blobs from {compression} RPA {rpa_name} (stream)")
                    sorted_blobs = sorted(blobs.items(), key=lambda x: x[1][0])
                    with zipfile.ZipFile(zip_path, 'r') as zf:
                        with zf.open(rpa_name) as stream:
                            current_pos = 0
                            for sha2, (rpa_offset, size) in sorted_blobs:
                                skip = rpa_offset - current_pos
                                if skip > 0:
                                    _consume(stream, skip)
                                    current_pos += skip
                                data = stream.read(size)
                                current_pos += len(data)
                                _verify_and_write(zout, sha2, data)
                                written += 1
                                if written % 100 == 0:
                                    print(f"  {written}/{total} entries written")

            print(f"  {written}/{total} entries written")

        final_size = os.path.getsize(update_zip_path)
        print(f"Wrote {update_zip_path} ({final_size} bytes)")


def _verify_and_write(zout, expected_hash, data):
    """Verify sha256 of data and write it to the output zip."""
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected_hash:
        print(f"Error: hash mismatch: expected {expected_hash}, got {actual}", file=sys.stderr)
        sys.exit(1)
    zout.writestr(expected_hash, data)


def _consume(stream, num_bytes):
    """Read and discard num_bytes from a stream."""
    remaining = num_bytes
    while remaining > 0:
        chunk = min(65536, remaining)
        data = stream.read(chunk)
        if not data:
            break
        remaining -= len(data)


if __name__ == '__main__':
    main()
