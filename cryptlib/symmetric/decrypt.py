from nacl.bindings import sodium_increment
from nacl import pwhash, secret
from cryptlib.constants import Constants
from pathlib import Path

# Type hint for list of bytes
bytelist = Constants().bytelist


def symmetric_decrypt(file: Path, password: str) -> bytelist:
    """Decrypts a file with a password and returns the decrypted chunks"""

    # Get the constants
    kdf, ops, mem, keysize, chunksize, macsize = Constants().all

    with open(file, "rb") as infile:
        outchunks = []

        # Read the salt, ops, mem, and nonce from the file
        salt = infile.read(pwhash.argon2i.SALTBYTES)
        encodedOps = infile.readline()
        encodedMem = infile.readline()
        nonce = infile.read(secret.SecretBox.NONCE_SIZE)
        ops = int(encodedOps.decode(encoding='UTF-8'))
        mem = int(encodedMem.decode(encoding='UTF-8'))

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
