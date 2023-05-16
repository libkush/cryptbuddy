from nacl.bindings import sodium_increment
from cryptlib.constants import *
from nacl import pwhash, secret, utils
from pathlib import Path


def symmetric_encrypt(file: Path, password: str = None, key: bytes = None) -> bytelist:
    """
    Encrypts a file with a password and returns the encrypted chunks
    """

    if not file.exists():
        raise FileNotFoundError("File does not exist")
    if not password and not key:
        raise ValueError("Password or key must be provided")

    # Generate the salt, nonce, and key using the password
    salt = utils.random(saltbytes)
    nonce = utils.random(noncesize)
    encodedOps = str(ops).encode(encoding='UTF-8')
    encodedMem = str(mem).encode(encoding='UTF-8')
    if not key:
        key = kdf(keysize, password.encode(),
                  salt, opslimit=ops, memlimit=mem)

    # Create the box and empty list for the chunks
    box = secret.SecretBox(key)
    outchunks = []

    with open(file, "rb") as infile:

        # Write the salt, ops, mem, and nonce to the file
        outchunks.append(salt)
        outchunks.append(encodedOps)
        outchunks.append(b'\n')
        outchunks.append(encodedMem)
        outchunks.append(b'\n')
        outchunks.append(nonce)
        outchunks.append(b'\n')

        # Encrypt the file data in chunks
        while 1:
            chunk = infile.read(chunksize)
            if len(chunk) == 0:
                break
            outchunk = box.encrypt(chunk, nonce).ciphertext
            assert len(outchunk) == len(chunk) + macsize
            outchunks.append(outchunk)
            nonce = sodium_increment(nonce)

    return outchunks
