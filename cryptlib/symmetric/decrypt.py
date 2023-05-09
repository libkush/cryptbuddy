from nacl.bindings import sodium_increment
from nacl import pwhash, secret
from pathlib import Path


def symmetric_decrypt(file: Path, password: str, config):
    chunksize = config.chunksize
    macsize = config.macsize
    kdf = pwhash.argon2i.kdf
    with open(file, "rb") as infile:
        outchunks = []
        salt = infile.read(pwhash.argon2i.SALTBYTES)
        encodedOps = infile.readline()
        encodedMem = infile.readline()
        nonce = infile.read(secret.SecretBox.NONCE_SIZE)
        ops = int(encodedOps.decode(encoding='UTF-8'))
        mem = int(encodedMem.decode(encoding='UTF-8'))
        key = kdf(secret.SecretBox.KEY_SIZE, password.encode(),
                  salt, opslimit=ops, memlimit=mem)
        box = secret.SecretBox(key)
        _newline = infile.read(1)
        while 1:
            rchunk = infile.read(chunksize + macsize)
            if len(rchunk) == 0:
                break
            dchunk = box.decrypt(rchunk, nonce)
            assert len(dchunk) == len(rchunk) - macsize
            outchunks.append(dchunk)
            nonce = sodium_increment(nonce)
    return outchunks
