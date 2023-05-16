from nacl.bindings import sodium_increment
from nacl import pwhash, secret
from cryptlib.constants import *
from pathlib import Path


def symmetric_decrypt(file: Path, password: str = None, key: bytes = None) -> bytelist:
    """
    Decrypts a file with a password and returns the decrypted chunks
    """

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

        if not key:
            # Generate the key from the password
            key = kdf(keysize, password.encode(),
                      salt, opslimit=ops, memlimit=mem)
        box = secret.SecretBox(key)
        _newline = infile.read(1)

        # Decrypt the file data in chunks
        while 1:
            rchunk = infile.read(chunksize + macsize)
            if len(rchunk) == 0:
                break
            dchunk = box.decrypt(rchunk, nonce)
            assert len(dchunk) == len(rchunk) - macsize
            outchunks.append(dchunk)
            nonce = sodium_increment(nonce)

    return outchunks
