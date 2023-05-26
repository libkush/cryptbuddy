from pathlib import Path
from typing import List

from nacl import pwhash, secret
from nacl.bindings import sodium_increment

from cryptbuddy.lib.constants import *
from cryptbuddy.lib.utils import info


def symmetric_decrypt(
    file: Path, password: str = None, key: bytes = None
) -> List[bytes]:
    """
    Decrypts a file symmetrically using a password or key.

    Parameters
    ----------
    file : `Path`
        The path to the file to be decrypted.
    password : `str`, optional
        The password used for decryption (default is `None`).
    key : `bytes`, optional
        The key used for decryption (default is `None`).

    Returns
    -------
    `List[bytes]`
        A list of decrypted data chunks.

    Raises
    ------
    `FileNotFoundError`
        If the specified file does not exist.
    `ValueError`
        If neither a password nor a key is provided.
    `Exception`
        If an error occurs during decryption.

    Note
    -----
    This function is used to decrypt files that were symmetrically encrypted
    using the `symmetric_encrypt` function.

    """

    info(f"Decrypting {file} symmetrically")

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
        ops = int(encodedOps.decode(encoding="UTF-8"))
        mem = int(encodedMem.decode(encoding="UTF-8"))

        # Generate the key from the password if not already provided
        if not key:
            key = KDF(KEYSIZE, password.encode(), salt, opslimit=ops, memlimit=mem)

        box = secret.SecretBox(key)
        _newline = infile.read(1)

        # Decrypt the file data in chunks of given size
        while 1:
            rchunk = infile.read(CHUNKSIZE + MACSIZE)
            if len(rchunk) == 0:
                break
            try:
                dchunk = box.decrypt(rchunk, nonce)
            except Exception as e:
                raise Exception("Error during decryption") from e
            assert len(dchunk) == len(rchunk) - MACSIZE
            outchunks.append(dchunk)
            nonce = sodium_increment(nonce)

    return outchunks
