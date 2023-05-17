from pathlib import Path

from cryptbuddy.cryptlib.constants import *
from nacl import pwhash, secret
from nacl.bindings import sodium_increment


def symmetric_decrypt(file: Path, password: str = None, key: bytes = None) -> bytelist:
    """
    Returns the decrypted chunks after symmetrically decrypting the file.
    `file` is the file to be decrypted. `password` is the password to be
    used to retrieve the key. `key` is the key to be used to decrypt the
    file. Either `password` or `key` must be provided.
    """

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
