from nacl import secret, pwhash
from typing import List


class Constants:
    """Cryptographic constants required by cryptbuddy"""

    def __init__(self):
        self.chunksize = 64 * 1024
        self.macsize = secret.SecretBox.MACBYTES
        self.ops = pwhash.argon2i.OPSLIMIT_SENSITIVE
        self.mem = pwhash.argon2i.MEMLIMIT_SENSITIVE
        self.kdf = pwhash.argon2i.kdf
        self.keysize = secret.SecretBox.KEY_SIZE
        self.all = (self.kdf, self.ops, self.mem,
                    self.keysize, self.chunksize, self.macsize)
        self.bytelist = List[bytes]
