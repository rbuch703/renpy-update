import base64
import zlib
import pickle

from lib.utils import hash_sha2

class RpaReader:
    """Class to read RPA archive files."""
    def __init__(self, file):
        self.file = file
        header = b''
        for byte in iter(lambda: self.file.read(1), b''):
            if byte == b'\n':
                break
            header += byte
        
        header_str = header.decode('utf-8')
        parts = header_str.split(' ')
        
        if parts[0] == "RPA-3.0":
            index_offset = int(parts[1], 16)
            assert len(parts[2]) == 8
            key_int = int(parts[2], 16)
            # Convert to little-endian bytes
            key = key_int.to_bytes(4, 'little')
        else:
            raise ValueError("Unsupported RPA version")

        self.index = _read_index(self.file, index_offset, key)
    
    def entries(self):
        """Return the decrypted index entries."""
        for file_name, (offset, size) in self.index.items():
            yield file_name, (offset, size)

    def files(self):
        """Generator yielding (file_name, file_contents) tuples."""
        for file_name, (offset, size) in self.index.items():
            self.file.seek(offset)
            contents = self.file.read(size)
            yield file_name, contents

    def content_map(self):
        """Create a content map of an RPA file that allows to recreate the whole file from individual components.

        Args:
            `base_offset`: If provided (even if `0`), all content references will contain an offset
            and size into the source RPA file. Offsets are shifted by `base_offset`, which allows
            to reference these files directly as indices into an outer container (e.g. a .zip or
            .tar file).
        """

        content = []
        for _file_name, (offset, size) in self.index.items():
            sha2 = self.hash_entry(offset, size)
            content.append((offset, size, sha2))

        # sort by order in archive
        content.sort()

        current_offset = 0
        current_index = 0
        res = []
        # Traverse the archive from start to finish, identifying gaps and entries
        while True:
            if current_index >= len(content):
                break
            entry_offset, entry_size, entry_sha2 = content[current_index]
            if current_offset < entry_offset:
                gap_size = entry_offset - current_offset
                # We're serializing the gaps as base64 to the package file.
                # Anything larger than 10MB is suspicious.
                assert gap_size < (10 * 1024 * 1024), "Gap too large!"
                self.file.seek(current_offset)
                contents = self.file.read(gap_size)
                res.append({"raw": base64.b64encode(contents).decode('utf-8')})
                current_offset += gap_size
            else:
                assert current_offset == entry_offset, "Overlapping entries in RPA"
                entry = {
                    "sha2": entry_sha2,
                }

                entry["offset"] = entry_offset
                entry["size"] = entry_size
                res.append(entry)
                current_offset += entry_size
                current_index += 1

        # Handle any remaining data at the end of the file        
        self.file.seek(current_offset)
        remaining = self.file.read()
        if remaining:
            res.append({"raw": base64.b64encode(remaining).decode('utf-8')})

        rpa = _try_convert_to_rpa(res)

        return [ "blob", res ] if rpa is None else ["rpa", rpa ]

    def hash_entry(self, offset, size):
        """Compute the SHA-256 hash of the RPA entry at `offset` with size `size`"""
        self.file.seek(offset)
        return hash_sha2(self.file, size)

def _try_convert_to_rpa(content):
    RPA_SPACER = b"Made with Ren'Py."

    rpa = []
    for i, entry in enumerate(content):
        is_raw = "raw" in entry
        if i == 0 or i == len(content) - 1:
            if not is_raw:
                # For proper RPAs, header and trailer must be raw
                return None
            rpa.append(entry)
        else:
            if is_raw:
                if i % 2 == 1:
                    # A RPA file is a sequence alternating between entries and raw data.
                    # Two raw data entries in a row are not allowed.
                    return None
                if base64.b64decode(entry["raw"]) != RPA_SPACER:
                    # Unrecognized raw data in the middle of the RPA
                    return None
                else:
                    # Don't serialize RPA spacers, they are implicit in the file format
                    pass
            elif "sha2" in entry:

                rpa.append(entry)
            else:
                assert False, "Invalid RPA content entry"
    return rpa


def _decode(v, key):
    """XOR decode a 32-bit value with a 4-byte key."""
    v_bytes = v.to_bytes(4, 'big')
    decoded = bytes([v_bytes[i] ^ key[i] for i in range(4)])
    return int.from_bytes(decoded, 'big')


def _read_index(file, index_offset, key):
    """Read and decrypt the RPA index from the archive.
    
    Args:
        file: Open file object for the RPA archive
        index_offset: Offset in the file where the index starts
        key: 4-byte XOR key used for decryption
    
    Returns:
        Dictionary mapping file names to (offset, size) tuples
    """    
    # Read and decompress the index
    file.seek(index_offset)
    compressed_index = file.read()
    
    decompressed_index = zlib.decompress(compressed_index)
    
    # Deserialize the pickle index
    index = pickle.loads(decompressed_index)
    
    # Decrypt the index entries
    decrypted_index = {}
    for file_name, value_tuple in index.items():
        # The value is a tuple containing the RpaDictionaryValue
        rpa_value = value_tuple[0]
        offset = rpa_value[0]
        size = rpa_value[1]
        # _unused = rpa_value[2]
        
        # Decrypt size
        size_bytes = size.to_bytes(4, 'big')
        size_decrypted = bytes([size_bytes[i] ^ key[i] for i in range(4)])
        size_decrypted = int.from_bytes(size_decrypted, 'big')
        
        # Decrypt offset
        offset_decrypted = _decode(offset, key)
        
        decrypted_index[file_name] = (offset_decrypted, size_decrypted)
    
    return decrypted_index

