#! /usr/bin/python3

import os
import sys
import zlib
import pickle


def decode(v, key):
    """XOR decode a 32-bit value with a 4-byte key."""
    v_bytes = v.to_bytes(4, 'big')
    decoded = bytes([v_bytes[i] ^ key[i] for i in range(4)])
    return int.from_bytes(decoded, 'big')


def read_and_decrypt_index(file_name, index_offset, key):
    """Read and decrypt the RPA index from the archive.
    
    Args:
        file_name: Path to the RPA archive file
        index_offset: Offset in the file where the index starts
        key: 4-byte XOR key used for decryption
    
    Returns:
        Dictionary mapping file names to (offset, size) tuples
    """    
    # Read and decompress the index
    with open(file_name, 'rb') as f:
        f.seek(index_offset)
        compressed_index = f.read()
    
    decompressed_index = zlib.decompress(compressed_index)
    print(f"Decompressed index has {len(decompressed_index)} bytes")
    
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
        offset_decrypted = decode(offset, key)
        
        decrypted_index[file_name] = (offset_decrypted, size_decrypted)
    
    return decrypted_index


def main():
    bundle_file_name = sys.argv[1]
    
    # Read header line
    f = open(bundle_file_name, 'rb')
    header = b''
    for byte in iter(lambda: f.read(1), b''):
        if byte == b'\n':
            break
        header += byte
    
    header_str = header.decode('utf-8')
    parts = header_str.split(' ')
    print(parts)
    
    if parts[0] == "RPA-3.0":
        index_offset = int(parts[1], 16)
        assert len(parts[2]) == 8
        key_int = int(parts[2], 16)
        # Convert to little-endian bytes
        key = key_int.to_bytes(4, 'little')
        print(f"offset: {index_offset}, key: {key}")

        decrypted_index = read_and_decrypt_index(bundle_file_name, index_offset, key)


        # Extract files
        os.makedirs('out', exist_ok=True)
        
        for file_name, (offset, size) in decrypted_index.items():
            file_name_safe = file_name.replace('/', '_')
            print(f"{file_name}: offset={offset}, size={size}")
            
            f.seek(offset)
            contents = f.read(size)
            
            output_path = os.path.join('out', file_name_safe)
            with open(output_path, 'wb') as f_out:
                f_out.write(contents)


if __name__ == '__main__':
    main()
