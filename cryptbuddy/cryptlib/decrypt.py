from pathlib import Path

from cryptbuddy.cryptlib.file_io import cache_dir, shred_file
from cryptbuddy.cryptlib.key_io import AppPrivateKey
from cryptbuddy.cryptlib.symmetric.decrypt import symmetric_decrypt
from msgpack import loads
from nacl.public import SealedBox


def asymmetric_decrypt(file: Path, password: str, private_key_object: AppPrivateKey):
    """
    Returns the decrypted chunks. `file` is the file to be 
    decrypted. `password` is the password of your private key. 
    `private_key_object` is the private key object.
    """

    # Get the decrypted NaCl private key object
    name = private_key_object.meta.name
    private_key = private_key_object.decrypted_key(password)

    # Create a sealed box with the private key
    unseal_box = SealedBox(private_key)

    # Read the serialized keys before the first newline
    with open(file, "rb") as infile:
        contents = infile.read()
        newline_index = contents.index(b'\n')
        packed_keys = contents[:newline_index]
        encrypted_chunks = contents[newline_index+1:]

    # Decrypt the symmetric key using your private key
    keys = loads(packed_keys)
    my_key = keys[name]
    symmetric_key = unseal_box.decrypt(my_key)

    # Store the encrypted chunks to a temporary file
    tmp = Path(f"{cache_dir}/{str(file)}")
    with open(tmp, "wb") as infile:
        infile.write(encrypted_chunks)

    # Decrypt the file using the symmetric key
    chunks = symmetric_decrypt(tmp, key=symmetric_key)

    # Shred the temporary file
    shred_file(tmp)

    # Return the decrypted chunks
    return chunks
