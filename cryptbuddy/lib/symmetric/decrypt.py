from pathlib import Path

from cryptbuddy.lib.constants import *
from nacl import pwhash, secret
from nacl.bindings import sodium_increment

from cryptbuddy.lib.utils import info


def symmetric_decrypt(file: Path, password: str = None, key: bytes = None) -> bytelist:
    """
    Decrypts a file using symmetric encryption with a password or key.

    This function reads an encrypted file and decrypts its contents using symmetric encryption.
    It requires either a password or a key for decryption.

    Args:
        file (Path): The path to the encrypted file.
        password (str, optional): The password used for decryption. Defaults to None.
        key (bytes, optional): The key used for decryption. Defaults to None.

    Returns:
        List[bytes]: A list of decrypted chunks of data.

    Raises:
        FileNotFoundError: If the specified file does not exist.
        ValueError: If neither a password nor a key is provided.

    Note:
        The file must have been encrypted using the corresponding `symmetric_encrypt` function.

    """

    info(f"Decrypting {file} symmetrically")

    # Check if the file exists and if the password or key is provided
    if not file.exists():
        raise FileNotFoundError("File does not exist")
    if not password and not key:
        raise ValueError("Password or key must be provided")

    with open(file, "rb") as infile:
        outchunks = []

        # Read the salt, ops, mem, and nonce from the file
        salt = infile.read(pwhash.argon2i.SALTBYTES)
        encodedOps = infile.readline()
        encodedMem = infile.readline()
        nonce = infile.read(secret.SecretBox.NONCE_SIZE)
        ops = int(encodedOps.decode(encoding='UTF-8'))
        mem = int(encodedMem.decode(encoding='UTF-8'))

        # Generate the key from the password if not already provided
        if not key:
            key = kdf(keysize, password.encode(),
                      salt, opslimit=ops, memlimit=mem)

        # Create the box
        box = secret.SecretBox(key)
        _newline = infile.read(1)

        # Decrypt the file data in chunks of given size
        while 1:
            rchunk = infile.read(chunksize + macsize)
            if len(rchunk) == 0:
                break
            dchunk = box.decrypt(rchunk, nonce)
            assert len(dchunk) == len(rchunk) - macsize
            outchunks.append(dchunk)
            nonce = sodium_increment(nonce)

    return outchunks
