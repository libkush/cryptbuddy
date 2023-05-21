from pathlib import Path

from cryptbuddy.lib.file_io import cache_dir, shred_file
from cryptbuddy.lib.key_io import AppPrivateKey
from cryptbuddy.lib.symmetric.decrypt import symmetric_decrypt
from cryptbuddy.lib.utils import info
from cryptbuddy.lib.constants import *
from msgpack import loads
from nacl.public import SealedBox


def asymmetric_decrypt(file: Path, password: str, private_key_object: AppPrivateKey):
    """
    Decrypts a file using asymmetric encryption with a password and private key.

    This function reads an encrypted file and decrypts its contents using asymmetric encryption.
    It requires a password and a private key object for decryption.

    Args:
        file (Path): The path to the encrypted file.
        password (str): The password used to decrypt the private key.
        private_key_object (AppPrivateKey): The private key object used for decryption.

    Raises:
        ValueError: If the password is incorrect or the private key cannot be decrypted.

    Returns:
        List[bytes]: A list of decrypted chunks of data.

    Note:
        The file must have been encrypted using the corresponding `asymmetric_encrypt` function.

    """

    info(f"Decrypting {file}")

    # Get the decrypted NaCl private key object
    name = private_key_object.meta.name
    private_key = private_key_object.decrypted_key(password)

    # Create a sealed box with the private key
    unseal_box = SealedBox(private_key)

    # Read the serialized keys before the first newline
    with open(file, "rb") as infile:
        file_data = infile.read()

    # Find the index of the first delimiter
    delimiter_index = file_data.find(delimiter)
    while delimiter_index > 0 and file_data[delimiter_index - len(escape_sequence):delimiter_index] == escape_sequence:
        # The delimiter is part of the packed keys, search for the next occurrence
        delimiter_index = file_data.find(delimiter, delimiter_index + 1)

    if delimiter_index == -1:
        raise ValueError("Delimiter not found or preceded by escape sequence")

    packed_keys = file_data[:delimiter_index]

    # Process the escape sequences within the packed keys
    packed_keys = packed_keys.replace(escape_sequence + delimiter, delimiter)

    # # Decrypt the symmetric key using your private key
    keys = loads(packed_keys)

    encrypted_chunks = file_data[delimiter_index + len(delimiter):]

    my_key = keys[name]
    symmetric_key = unseal_box.decrypt(my_key)

    # Store the encrypted chunks to a temporary file
    tmp = Path(f"{cache_dir}/{str(file.name)}")
    with open(tmp, "wb") as infile:
        infile.write(encrypted_chunks)

    # Decrypt the file using the symmetric key
    chunks = symmetric_decrypt(tmp, key=symmetric_key)

    # Shred the temporary file
    shred_file(tmp)

    # Return the decrypted chunks
    return chunks
