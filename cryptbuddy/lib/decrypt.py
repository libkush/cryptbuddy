from pathlib import Path
from typing import List

from msgpack import loads
from nacl.public import SealedBox

from cryptbuddy.lib.constants import *
from cryptbuddy.lib.file_io import cache_dir, shred_file
from cryptbuddy.lib.key_io import AppPrivateKey
from cryptbuddy.lib.symmetric.decrypt import symmetric_decrypt
from cryptbuddy.lib.utils import info


def asymmetric_decrypt(
    file: Path, password: str, private_key_object: AppPrivateKey
) -> List[bytes]:
    """
    Decrypts a file asymmetrically a private key. The file must have been encrypted using the corresponding
    `asymmetric_encrypt` function.

    Parameters
    ----------
    file : `Path`
        The path to the file to be decrypted.
    password : `str`
        The password used for decryption.
    private_key_object : `AppPrivateKey`
        The private key object used for decryption.

    Returns
    -------
    `List[bytes]`
        A list of decrypted data chunks.

    Raises
    ------
    `ValueError`
        If the delimiter is not found or is preceded by an escape sequence.
    `Exception`
        If an error occurs during decryption.

    Notes
    -----
    The file must have been encrypted using the corresponding `asymmetric_encrypt` function.

    """

    info(f"Decrypting {file}")

    # Get the decrypted NaCl private key object
    name = private_key_object.meta.name
    private_key = private_key_object.decrypted_key(password)

    unseal_box = SealedBox(private_key)

    # Read the serialized keys before the first newline
    with open(file, "rb") as infile:
        file_data = infile.read()

    # Find the index of the first delimiter
    delimiter_index = file_data.find(DELIMITER)
    while (
        delimiter_index > 0
        and file_data[delimiter_index - len(ESCAPE_SEQUENCE) : delimiter_index]
        == ESCAPE_SEQUENCE
    ):
        # The delimiter is part of the packed keys, search for the next occurrence
        delimiter_index = file_data.find(DELIMITER, delimiter_index + 1)

    if delimiter_index == -1:
        raise ValueError("Delimiter not found or preceded by escape sequence")

    packed_keys = file_data[:delimiter_index]
    encrypted_chunks = file_data[delimiter_index + len(DELIMITER) :]

    # Process the escape sequences within the packed keys
    packed_keys = packed_keys.replace(ESCAPE_SEQUENCE + DELIMITER, DELIMITER)

    keys = loads(packed_keys)
    my_key = keys[name]
    symmetric_key = unseal_box.decrypt(my_key)

    # Store the encrypted chunks to a temporary file
    tmp = Path(f"{cache_dir}/{str(file.name)}")
    with open(tmp, "wb") as infile:
        infile.write(encrypted_chunks)

    try:
        # Decrypt the file using the symmetric key
        chunks = symmetric_decrypt(tmp, key=symmetric_key)
    except Exception as e:
        raise Exception("Error decrypting file") from e

    # Shred the temporary file
    shred_file(tmp)

    return chunks
