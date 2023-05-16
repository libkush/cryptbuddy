from pathlib import Path
from cryptlib.key_io import AppPrivateKey
from nacl.public import PrivateKey, SealedBox
from msgpack import loads
from cryptlib.file_io import cache_dir, shred_file
from cryptlib.symmetric.decrypt import symmetric_decrypt


def asymmetric_decrypt(file: Path, password: str, private_key_object: AppPrivateKey):
    name = private_key_object.meta.name
    private_key = PrivateKey(private_key_object.decrypted_key(password))
    unseal_box = SealedBox(private_key)
    with open(file, "rb") as infile:
        contents = infile.read()
        newline_index = contents.index(b'\n')
        packed_keys = contents[:newline_index]
        encrypted_chunks = contents[newline_index+1:]
    tmp = Path(f"{cache_dir}/{str(file)}")
    with open(tmp, "wb") as infile:
        infile.write(encrypted_chunks)
    keys = loads(packed_keys)
    my_key = keys[name]
    symmetric_key = unseal_box.decrypt(my_key)
    chunks = symmetric_decrypt(tmp, key=symmetric_key)
    shred_file(tmp)
    return chunks
