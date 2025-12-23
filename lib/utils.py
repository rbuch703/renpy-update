
import hashlib


def hash_sha2(file, num_bytes=None):
    """Calculate the SHA-256 hash of a file-like object up to size bytes."""
    hasher = hashlib.sha256()
    remaining = num_bytes if num_bytes is not None else float('inf')
    BUFFER_SIZE = 65536  # 64KB buffer

    while remaining > 0:
        read_size = min(BUFFER_SIZE, remaining)
        data = file.read(read_size)
        if not data:
            break
        hasher.update(data)
        remaining -= len(data)

    return hasher.hexdigest()

# Compression type names
COMPRESSION_NAMES = {
    0: "STORED",
    8: "DEFLATED",
    12: "BZIP2",
    14: "LZMA"
}

def get_zip_entry_offset(zip_file, info):
            # Calculate actual data offset
        # Local file header: 30 bytes + filename length + extra field length
        zip_file.seek(info.header_offset)
        
        # Read local file header
        local_header = zip_file.read(30)
        filename_len = int.from_bytes(local_header[26:28], 'little')
        extra_len = int.from_bytes(local_header[28:30], 'little')
        
        # Actual data starts after local header + filename + extra field
        return info.header_offset + 30 + filename_len + extra_len
