from pathlib import Path

from cryptbuddy.cryptlib.constants import *
from nacl import secret, utils
from nacl.bindings import sodium_increment


def symmetric_encrypt(file: Path, password: str = None, key: bytes = None) -> bytelist:
    """
    Returns the encrypted chunks after symmetrically encrypting the file.
    `file` is the file to be encrypted. `password` is the password to be
    used to generate the key. `key` is the key to be used to encrypt the
    file. Either `password` or `key` must be provided.
    """

    # Check if the file exists and if the password or key is provided
    if not file.exists():
        raise FileNotFoundError("File does not exist")
    if not password and not key:
        raise ValueError("Password or key must be provided")

    # Generate the salt and nonce
    salt = utils.random(saltbytes)
    nonce = utils.random(noncesize)
    encodedOps = str(ops).encode(encoding='UTF-8')
    encodedMem = str(mem).encode(encoding='UTF-8')

    # Generate the key using the password if not already provided
    if not key:
        key = kdf(keysize, password.encode(),
                  salt, opslimit=ops, memlimit=mem)

    # Create the box and empty list for the chunks
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
            chunk = infile.read(chunksize)
            if len(chunk) == 0:
                break
            outchunk = box.encrypt(chunk, nonce).ciphertext
            assert len(outchunk) == len(chunk) + macsize
            outchunks.append(outchunk)
            nonce = sodium_increment(nonce)

    return outchunks
