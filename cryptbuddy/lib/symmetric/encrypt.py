from pathlib import Path
from typing import List

from cryptbuddy.lib.constants import *
from cryptbuddy.lib.utils import info
from nacl import secret, utils
from nacl.bindings import sodium_increment


def symmetric_encrypt(file: Path, password: str = None, key: bytes = None) -> List[bytes]:
    """
    Encrypts a file symmetrically using a password or key. The file is
    encrypted in chunks of given size, and the salt, ops, mem, and nonce
    are prepended to the encrypted data.

    Parameters
    ----------
    file : `Path`
        The path to the file to be encrypted.
    password : `str`, optional
        The password used for encryption (default is `None`).
    key : `bytes`, optional
        The key used for encryption (default is `None`).

    Returns
    -------
    `List[bytes]`
        A list of encrypted data chunks.

    Raises
    ------
    `FileNotFoundError`
        If the specified file does not exist.
    `ValueError`
        If neither a password nor a key is provided.
    `Exception`
        If an error occurs during encryption.

    Note
    ----
    The file must be decrypted using the corresponding `symmetric_decrypt` function.

    """

    info(f"Encrypting {file} symmetrically")

    if not file.exists():
        raise FileNotFoundError("File does not exist")
    if not password and not key:
        raise ValueError("Password or key must be provided")

    salt = utils.random(SALTBYTES)
    nonce = utils.random(NONCESIZE)
    encodedOps = str(OPS).encode(encoding='UTF-8')
    encodedMem = str(MEM).encode(encoding='UTF-8')

    # Generate the key using the password if not already provided
    if not key:
        key = KDF(KEYSIZE, password.encode(),
                  salt, opslimit=OPS, memlimit=MEM)

    box = secret.SecretBox(key)
    outchunks = []

    with open(file, "rb") as infile:

        # Append the salt, ops, mem, and nonce to the chunks
        outchunks.append(salt)
        outchunks.append(encodedOps)
        outchunks.append(b'\n')
        outchunks.append(encodedMem)
        outchunks.append(b'\n')
        outchunks.append(nonce)
        outchunks.append(b'\n')

        # Encrypt the file data in chunks of given size
        while 1:
            chunk = infile.read(CHUNKSIZE)
            if len(chunk) == 0:
                break
            try:
                outchunk = box.encrypt(chunk, nonce).ciphertext
            except Exception as e:
                raise Exception("Error during encryption") from e
            assert len(outchunk) == len(chunk) + MACSIZE
            outchunks.append(outchunk)
            nonce = sodium_increment(nonce)

    return outchunks
