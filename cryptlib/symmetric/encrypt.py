from nacl.bindings import sodium_increment
from nacl import pwhash, secret, utils
from pathlib import Path


def encrypt(file: Path, password: str, config):
    chunksize = config.chunksize
    macsize = config.macsize
    kdf = pwhash.argon2i.kdf
    ops = pwhash.argon2i.OPSLIMIT_SENSITIVE
    salt = utils.random(pwhash.argon2i.SALTBYTES)
    mem = pwhash.argon2i.MEMLIMIT_SENSITIVE
    nonce = utils.random(secret.SecretBox.NONCE_SIZE)
    encodedOps = str(ops).encode(encoding='UTF-8')
    encodedOps = str(ops).encode(encoding='UTF-8')
    encodedMem = str(mem).encode(encoding='UTF-8')
    key = kdf(secret.SecretBox.KEY_SIZE, password.encode(),
              salt, opslimit=ops, memlimit=mem)
    box = secret.SecretBox(key)
    with open(file, "rb") as infile:
        # save encrypted file
        with open(f"{file}.enc", "wb") as f:
            f.write(salt)
            f.write(encodedOps)
            f.write(b'\n')
            f.write(encodedMem)
            f.write(b'\n')
            f.write(nonce)
            f.write(b'\n')
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outchunk = box.encrypt(chunk, nonce).ciphertext
                assert len(outchunk) == len(chunk) + macsize
                f.write(outchunk)
                nonce = sodium_increment(nonce)
