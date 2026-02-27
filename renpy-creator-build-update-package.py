#!/usr/bin/env python3
import argparse
import hashlib
import os
import sys
import zipfile

from lib.manifest import (
    extract_leaf_hashes,
    extract_leaf_hash_names,
    generate_manifests,
)

def main():
    """Generate an update package by comparing source and destination zip files."""
    parser = argparse.ArgumentParser(description='Process manifest and source files')
    parser.add_argument('--source', action='append', required=True, nargs='+', help='Source zip file(s), can be specified multiple times')
    parser.add_argument('--dest', action='append',   required=True, nargs='+', help='Destination zip file(s), can be specified multiple times')
    parser.add_argument('--verbose', action='store_true', help='Print detailed per-hash info for added and dropped entries')

    args = parser.parse_args()

    source_zip_paths = [p for g in args.source for p in g]
    dest_zip_paths = [p for g in args.dest for p in g]
    all_zip_paths = source_zip_paths + dest_zip_paths

    # --- 0. Validate zips and load/generate manifests ---
    manifests = generate_manifests(all_zip_paths)

    # --- 1. Source: intersection of leaf hashes across ALL source manifests ---
    source_hashes = None
    for zip_path in source_zip_paths:
        leaf = extract_leaf_hashes(manifests[zip_path])
        if source_hashes is None:
            source_hashes = dict(leaf)
        else:
            # Keep only hashes present in every source manifest
            source_hashes = {h: source_hashes[h] for h in source_hashes if h in leaf}
    if source_hashes is None:
        source_hashes = {}

    # --- 2. Dest: generate list of all files present in any of the destination zip files. ---
    dest_hashes = set()
    for zip_path in dest_zip_paths:
        dest_hashes.update(extract_leaf_hashes(manifests[zip_path]).keys())

    # --- 3. Diff: entries in dest but not in source -> those are new and need to be put into the update package ---
    diff_hashes = dest_hashes - set(source_hashes)

    if args.verbose:
        print_status(source_zip_paths, dest_zip_paths, manifests, source_hashes, dest_hashes, diff_hashes)

    if not diff_hashes:
        print("\nNo differences found. No update package needed.")
        return

    # --- Build update zip containing all added blobs ---
    update_zip_path = "update.zip"
    print(f"\nBuilding {update_zip_path} with {len(diff_hashes)} entries ...")

    regular_plan, rpa_plan = build_extraction_plan(diff_hashes, [(p, manifests[p]) for p in dest_zip_paths])
    total = len(diff_hashes)
    written = 0
    with zipfile.ZipFile(update_zip_path, 'w', compression=zipfile.ZIP_DEFLATED) as zout:
        def on_blob_retrieved(sha2, data):
            nonlocal written
            actual = hashlib.sha256(data).hexdigest()
            if actual != sha2:
                print(f"Error: hash mismatch: expected {sha2}, got {actual}", file=sys.stderr)
                sys.exit(1)
            zout.writestr(sha2, data)
            written += 1
            if written % 1000 == 0:
                print(f"  {written}/{total} entries written")
        build_update_package(on_blob_retrieved, regular_plan, rpa_plan)
    print(f"  {written}/{total} entries written")

    final_size = os.path.getsize(update_zip_path)
    print(f"Wrote {update_zip_path} ({final_size} bytes)")

def build_update_package(on_blob_retrieved, regular_plan, rpa_plan):
    """Extract all blobs in the extraction plans and emit them via callback.

    Regular zip entries are read directly; STORED RPA entries are accessed via
    raw byte-range seeks; compressed RPA entries are streamed in offset order.

    Args:
        on_blob_retrieved: Callback(sha2, data) invoked for each verified blob.
        regular_plan:      dict of sha2 -> (zip_path, zip_entry_name).
        rpa_plan:          dict of (zip_path, rpa_entry_name) ->
                               {"meta": {"compression", "zip_data_offset"},
                                "blobs": {sha2: (rpa_offset, size)}}.
    """
    # Regular files — one zip.read() each, grouped by source zip
    by_zip = {}
    for sha2, (zpath, zname) in regular_plan.items():
        by_zip.setdefault(zpath, []).append((sha2, zname))

    for zpath, entries in by_zip.items():
        with zipfile.ZipFile(zpath, 'r') as zf:
            for sha2, zname in entries:
                data = zf.read(zname)
                on_blob_retrieved(sha2, data)

    # RPA files — one pass per RPA
    for (zpath, rpa_name), plan in rpa_plan.items():
        blobs = plan["blobs"]
        compression = plan["meta"]["compression"]
        zip_data_offset = plan["meta"]["zip_data_offset"]

        if compression == "STORED":
            print(f"  Extracting {len(blobs)} blobs from STORED RPA {rpa_name} (direct)")
            with open(zpath, 'rb') as raw:
                for sha2, (rpa_offset, size) in blobs.items():
                    abs_offset = zip_data_offset + rpa_offset
                    raw.seek(abs_offset)
                    data = raw.read(size)
                    on_blob_retrieved(sha2, data)
        else:
            print(f"  Extracting {len(blobs)} blobs from {compression} RPA {rpa_name} (stream)")
            with zipfile.ZipFile(zpath, 'r') as zf:
                with zf.open(rpa_name) as stream:
                    stream_read_blobs(stream, blobs, on_blob_retrieved)


def stream_read_blobs(stream, blobs, on_blob_retrieved):
    """Read blobs from an open stream in sorted offset order.

    Seeks forward over gaps between blobs and calls on_blob_retrieved() for each
    blob read. This guarantees that each byte in `stream` is read at most once.

    Args:
        stream:            Open readable/seekable stream (e.g. ZipExtFile).
        blobs:      Iterable of (sha2, (rpa_offset, size)).
        on_blob_retrieved: Callback(sha2, data) for each blob.
    """
    sorted_blobs = sorted(blobs.items(), key=lambda x: x[1][0])
    current_pos = 0

    for sha2, (rpa_offset, size) in sorted_blobs:
        skip = rpa_offset - current_pos
        if skip > 0:
            stream.seek(skip, 1)
            current_pos += skip
        data = stream.read(size)
        current_pos += len(data)
        on_blob_retrieved(sha2, data)


def build_extraction_plan(hashes, manifests):
    """Build extraction plans for all hashes.

    Scans manifests and records exactly where each needed hash can be
    found, separating regular zip entries from RPA sub-entries so callers
    can use the most efficient read strategy for each.

    Args:
        hashes:    set of sha2 hex-digests for blobs that must be extracted.
        manifests: ordered list of (zip_path, manifest_data) pairs to search.

    Returns:
        regular_plan: dict of sha2 -> (zip_path, zip_entry_name)
        rpa_plan:     dict of (zip_path, rpa_entry_name) ->
                          {"meta": {"compression", "zip_data_offset"},
                           "blobs": {sha2: (rpa_offset, size)}}

    Exits with an error if any hash in hashes cannot be located.
    """
    remaining = set(hashes)
    regular_plan = {} # sha2 -> (zip_path, zip_entry_name)
    rpa_plan = {}     # (zip_path, rpa_name) -> {"meta": {...}, "blobs": {sha2: (offset, size)}}

    for zip_path, manifest_data in manifests:
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
                    key = (zip_path, entry_name)
                    rpa_plan[key] = {
                        "meta": {
                            "compression": props['compression'],
                            "zip_data_offset": props['offset'],
                        },
                        "blobs": blobs_here,
                    }
            else:
                if 'sha2' in props and props['sha2'] in remaining:
                    regular_plan[props['sha2']] = (zip_path, entry_name)
                    remaining.discard(props['sha2'])

    if remaining:
        print(f"Error: {len(remaining)} hashes not found in any dest manifest", file=sys.stderr)
        sys.exit(1)

    return regular_plan, rpa_plan

def print_status(source_zip_paths, dest_zip_paths, manifests, source_hashes, dest_hashes, diff_hashes):
    """Print a detailed summary of source/dest hash counts and per-hash details.

    Prints hash counts for source, dest, dropped, and added sets, then lists
    each dropped hash with its size and name (sorted largest-first) and each
    added hash with its name.

    Args:
        source_zip_paths: List of source zip paths (for name lookup).
        dest_zip_paths:   List of dest zip paths (for name lookup).
        manifests:        dict of zip_path -> manifest_data.
        source_hashes:    dict of sha2 -> size for the source intersection.
        dest_hashes:      set of sha2 for the dest union.
        diff_hashes:      set of sha2 for blobs added in dest.
    """
    dropped_hashes = {h: size for h, size in source_hashes.items() if h not in dest_hashes}
    print()
    print(f"Source:  {len(source_hashes)} hashes, {sum(source_hashes.values())} bytes")
    print(f"- dropped: {len(dropped_hashes)} hashes, {sum(dropped_hashes.values())} bytes")
    print(f"Dest:    {len(dest_hashes)} hashes")
    print(f"- added:    {len(diff_hashes)} hashes")

    # Build hash -> name mappings from the relevant manifests
    source_names = {}
    for zip_path in source_zip_paths:
        source_names.update(extract_leaf_hash_names(manifests[zip_path]))

    dest_names = {}
    for zip_path in dest_zip_paths:
        dest_names.update(extract_leaf_hash_names(manifests[zip_path]))

    if dropped_hashes:
        print("\nDropped hashes:")
        for h, size in sorted(dropped_hashes.items(), key=lambda x: -x[1]):
            name, _ = source_names.get(h, ('(unknown)', 0))
            print(f"  {h} {size:>12}  {name}")

    if diff_hashes:
        print("\nAdded hashes:")
        for h in sorted(diff_hashes, key=lambda h: -dest_names.get(h, ('', 0))[1]):
            name, size = dest_names.get(h, ('(unknown)', 0))
            print(f"  {h} {size:>12}  {name}")



if __name__ == '__main__':
    main()
