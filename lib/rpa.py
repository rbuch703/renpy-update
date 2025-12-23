import base64
import hashlib
import zlib
import pickle

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

        self.decrypted_index = _read_and_decrypt_index(self.file, index_offset, key)
    
    def entries(self):
        """Return the decrypted index entries."""
        for file_name, (offset, size) in self.decrypted_index.items():
            yield file_name, (offset, size)

    def files(self):
        """Generator yielding (file_name, file_contents) tuples."""
        for file_name, (offset, size) in self.decrypted_index.items():
            self.file.seek(offset)
            contents = self.file.read(size)
            yield file_name, contents

    def content_map(self):
        """Static method to create a content map of an RPA file."""

        content = []
        for _file_name, (offset, size) in self.decrypted_index.items():
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
                res.append(("raw", base64.b64encode(contents).decode('utf-8')))
                current_offset += gap_size
            else:
                assert current_offset == entry_offset
                res.append(("sha2", entry_sha2))
                current_offset += entry_size
                current_index += 1

        # Handle any remaining data at the end of the file        
        self.file.seek(current_offset)
        remaining = self.file.read()
        if remaining:
            res.append(("raw", base64.b64encode(remaining).decode('utf-8')))

        return res

    def hash_entry(self, offset, size):
        sha2 = hashlib.sha256()
        self.file.seek(offset)
        remaining = size
        while remaining > 0:
            chunk_size = min(65536, remaining)
            chunk = self.file.read(chunk_size)
            sha2.update(chunk)
            remaining -= chunk_size
        sha2 = sha2.hexdigest()
        return sha2

def _decode(v, key):
    """XOR decode a 32-bit value with a 4-byte key."""
    v_bytes = v.to_bytes(4, 'big')
    decoded = bytes([v_bytes[i] ^ key[i] for i in range(4)])
    return int.from_bytes(decoded, 'big')


def _read_and_decrypt_index(file, index_offset, key):
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

