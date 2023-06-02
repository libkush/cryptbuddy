from typing import List

from nacl.pwhash.argon2i import kdf

from cryptbuddy.structs.app_keys import AppPrivateKey, AppPublicKey


class EncryptOptions(object):
    def __init__(
        self,
        nonce: bytes,
        salt: bytes,
        keysize: int,
        macsize: int,
        chunksize: int,
        mem: int,
        ops: int,
        shred: bool,
    ):
        self.keysize = keysize
        self.chunksize = chunksize
        self.macsize = macsize
        self.noncesize = len(nonce)
        self.saltbytes = len(salt)
        self.salt = salt
        self.nonce = nonce
        self.mem = mem
        self.ops = ops
        self.shred = shred


class DecryptOptions(object):
    def __init__(
        self,
        shred: bool,
    ):
        self.shred = shred


class SymmetricEncryptOptions(EncryptOptions):
    def __init__(
        self,
        password: str,
        *args,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.type = "symmetric"
        self.key = kdf(
            self.keysize,
            password.encode(),
            self.salt,
            memlimit=self.mem,
            opslimit=self.ops,
        )


class SymmetricDecryptOptions(DecryptOptions):
    def __init__(
        self,
        password: str,
        *args,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.type = "symmetric"
        self.password = password

    def get_key(self, salt: bytes, mem, ops, keysize):
        return kdf(
            keysize,
            self.password.encode(),
            salt,
            memlimit=mem,
            opslimit=ops,
        )


class AsymmetricEncryptOptions(EncryptOptions):
    def __init__(self, symkey: bytes, public_keys: List[AppPublicKey], *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.public_keys = public_keys
        self.symkey = symkey
        self.keysize = len(symkey)
        self.type = "asymmetric"


class AsymmetricDecryptOptions(DecryptOptions):
    def __init__(
        self, user: str, private_key: AppPrivateKey, password: str, *args, **kwargs
    ):
        super().__init__(*args, **kwargs)
        self.user = user
        self.password = password
        self.private_key = private_key
        self.type = "asymmetric"
