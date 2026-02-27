"""Low-level manifest handling: generating, reading, and verifying manifests."""

import base64
import json
import sys
import zipfile

from lib.rpa import RpaReader
from lib.utils import COMPRESSION_NAMES, hash_sha2, get_zip_entry_offset


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def manifest_zip_path(manifest_path):
    """Derive the zip file path from a manifest path by stripping '.manifest'."""
    if manifest_path.endswith('.manifest'):
        return manifest_path[:-len('.manifest')]
    return manifest_path


def load_manifest(manifest_path):
    """Load and return the parsed JSON data from a manifest file."""
    with open(manifest_path, 'r', encoding='utf-8') as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Manifest generation
# ---------------------------------------------------------------------------

def generate_manifest(zip_path):
    """Generate a manifest dict from a zip file.

    Returns:
        dict: The manifest data (filename -> properties).
    """
    files = {}

    zf = zipfile.ZipFile(zip_path, 'r')
    raw_zip = open(zip_path, 'rb')
    print(f"Parsing zip file `{zip_path}`")
    for info in zf.infolist():
        if info.is_dir():
            assert info.filename not in files, "Duplicate file in package!"
            files[info.filename] = {
                "directory": True
            }
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
                key, contents = reader.content_map()
                assert key not in entry
                entry[key] = contents

            files[info.filename] = entry

    raw_zip.close()
    zf.close()
    return files


def write_manifest(manifest_data, manifest_path):
    """Write manifest data to a JSON file."""
    with open(manifest_path, 'w') as f:
        json.dump(manifest_data, f, indent=2)


# ---------------------------------------------------------------------------
# Manifest reading / querying
# ---------------------------------------------------------------------------

def extract_leaf_hashes(manifest_path):
    """Extract all sha2 hashes from leaf files (not intermediate files) in a manifest.

    Leaf files are:
    - Regular (non-RPA) file entries: their top-level sha2 with compressed_size
    - RPA sub-entries that have a sha2 (excluding 'raw' entries and the
      RPA file's own top-level sha2, which is an intermediate/composite hash)

    Skipped entries:
    - Directories
    - RPA top-level sha2 (intermediate)
    - RPA sub-entries with only 'raw' data (no sha2)

    Returns:
        dict: A mapping of sha2 hex-digest strings to object size for all leaf files.
              Regular files use 'compressed_size', RPA sub-entries use 'size'.
    """
    manifest_data = load_manifest(manifest_path)

    def _add_hash(hashes, sha2, size):
        if sha2 in hashes:
            if hashes[sha2] != size:
                print(f"Error: hash {sha2} has conflicting sizes: {hashes[sha2]} vs {size}",
                      file=sys.stderr)
                sys.exit(1)
        else:
            hashes[sha2] = size

    hashes = {}
    for _name, props in manifest_data.items():
        if props.get('directory'):
            continue
        if 'rpa' in props:
            for entry in props['rpa']:
                if 'sha2' in entry:
                    _add_hash(hashes, entry['sha2'], entry['size'])
        else:
            if 'sha2' in props:
                _add_hash(hashes, props['sha2'], props['compressed_size'])
    return hashes


def extract_leaf_hash_names(manifest_path):
    """Build a mapping from leaf sha2 hashes to a human-readable name.

    For regular files, the name is the zip entry path.
    For RPA sub-entries, the name indicates the containing RPA archive.

    Returns:
        dict: sha2 -> descriptive name string.
    """
    manifest_data = load_manifest(manifest_path)

    names = {}
    for entry_name, props in manifest_data.items():
        if props.get('directory'):
            continue
        if 'rpa' in props:
            for entry in props['rpa']:
                if 'sha2' in entry:
                    names.setdefault(entry['sha2'], f"(in RPA {entry_name})")
        else:
            if 'sha2' in props:
                names.setdefault(props['sha2'], entry_name)
    return names


def extract_blob_from_manifest(manifest_path, target_hash):
    """Find a hash in a manifest and extract its raw bytes from the corresponding zip.

    For regular files, extracts the decompressed file content from the zip entry.
    For RPA chunks, opens the decompressed RPA stream and reads the chunk at its offset.

    Returns:
        bytes if found, None otherwise.
    """
    manifest_data = load_manifest(manifest_path)
    zip_path = manifest_zip_path(manifest_path)

    for name, props in manifest_data.items():
        if props.get('directory'):
            continue
        if 'rpa' in props:
            for entry in props['rpa']:
                if entry.get('sha2') == target_hash:
                    with zipfile.ZipFile(zip_path, 'r') as zf:
                        with zf.open(name) as rpa_stream:
                            rpa_stream.seek(entry['offset'])
                            return rpa_stream.read(entry['size'])
        else:
            if props.get('sha2') == target_hash:
                with zipfile.ZipFile(zip_path, 'r') as zf:
                    return zf.read(name)
    return None


# ---------------------------------------------------------------------------
# Manifest verification
# ---------------------------------------------------------------------------

def verify_manifest(manifest_path):
    """Verify a manifest against its corresponding zip file.

    Returns:
        (errors, warnings) - lists of error/warning message strings.
    """
    manifest_data = load_manifest(manifest_path)
    zip_path = manifest_zip_path(manifest_path)

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
            continue

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
            _verify_rpa_entries(zf, name, rpa_entries, errors)

    raw_zip.close()
    zf.close()
    return errors, warnings


def _verify_rpa_entries(zf, zip_entry_name, rpa_entries, errors):
    """Verify RPA/blob sub-entries against the decompressed RPA stream."""
    try:
        rpa_stream = zf.open(zip_entry_name)
    except Exception as e:
        errors.append(f"{zip_entry_name}: cannot open for RPA verification: {e}")
        return

    for i, entry in enumerate(rpa_entries):
        if 'raw' in entry:
            expected_bytes = base64.b64decode(entry['raw'])
            offset = entry.get('offset')
            if offset is not None:
                rpa_stream.seek(offset)
                actual_bytes = rpa_stream.read(len(expected_bytes))
            else:
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
