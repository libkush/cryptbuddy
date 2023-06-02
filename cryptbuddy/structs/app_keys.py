from pathlib import Path

from nacl.public import PrivateKey, PublicKey
from nacl.pwhash.argon2i import kdf
from nacl.utils import random

from cryptbuddy.constants import (
    CHUNKSIZE,
    DELIMITER,
    ESCAPE_SEQUENCE,
    KEYSIZE,
    MACSIZE,
    MEM,
    NONCESIZE,
    OPS,
    SALTBYTES,
    SHRED,
    TAR,
)
from cryptbuddy.functions.file_data import add_meta, divide_in_chunks, parse_data
from cryptbuddy.functions.file_io import shred, write_bytes, write_chunks
from cryptbuddy.functions.symmetric import decrypt_data, encrypt_data


class KeyMeta:
    def __init__(self, name: str, email: str):
        self.name = name
        self.email = email
        self.keysize = KEYSIZE
        self.chunksize = CHUNKSIZE
        self.macsize = MACSIZE
        self.noncesize = NONCESIZE
        self.saltbytes = SALTBYTES
        self.ops = OPS
        self.mem = MEM


class BaseKey:
    def __init__(self, name: str, email: str):
        self.meta = KeyMeta(name, email)


class AppPrivateKey(BaseKey):
    def __init__(self, key: PrivateKey, password: str, *args, **kwargs):
        super().__init__(*args, **kwargs)
        nonce = random(self.meta.noncesize)
        salt = random(self.meta.saltbytes)
        metadata = {
            "type": "CB_PRI_KEY",
            "nonce": nonce,
            "salt": salt,
            "ops": self.meta.ops,
            "mem": self.meta.mem,
            "chunksize": self.meta.chunksize,
            "macsize": self.meta.macsize,
            "keysize": self.meta.keysize,
            "name": self.meta.name,
            "email": self.meta.email,
        }
        symkey = kdf(
            self.meta.keysize,
            password.encode(),
            salt,
            self.meta.ops,
            self.meta.mem,
        )
        encrypted_data = encrypt_data(
            key.encode(),
            symkey,
            nonce,
            self.meta.chunksize,
            self.meta.macsize,
        )
        data = add_meta(metadata, encrypted_data, DELIMITER, ESCAPE_SEQUENCE)
        self.data = b"".join(data)

    def __repr__(self):
        return f"<PrivateKey {self.meta.name} {self.meta.email}>"

    def __str__(self):
        return f"<PrivateKey {self.meta.name} {self.meta.email}>"

    def save(self, path: Path):
        if path.exists():
            raise FileExistsError("File already exists")
        write_bytes(self.data, path)

    @classmethod
    def decrypt_key(cls, data: bytes, password: str):
        meta, data = parse_data(data, DELIMITER, ESCAPE_SEQUENCE)
        symkey = kdf(
            size=meta["keysize"],
            password=password.encode(),
            salt=meta["salt"],
            opslimit=meta["ops"],
            memlimit=meta["mem"],
        )
        decrypted_data = b"".join(
            decrypt_data(
                data, meta["chunksize"], symkey, meta["nonce"], meta["macsize"]
            )
        )
        private_key = PrivateKey(decrypted_data)
        return private_key, meta

    def decrypted_key(self, password: str) -> PrivateKey:
        private_key, _meta = self.decrypt_key(self.data, password)
        return private_key

    @classmethod
    def from_data(cls, packed: bytes, password: str) -> "AppPrivateKey":
        decrypted_key, meta = cls.decrypt_key(packed, password)
        return AppPrivateKey(
            decrypted_key, password, name=meta["name"], email=meta["email"]
        )

    @classmethod
    def from_file(cls, file: Path, password: str) -> "AppPrivateKey":
        if not (file.exists() or file.is_file()):
            raise FileNotFoundError("File does not exist")
        data = file.read_bytes()
        return cls.from_data(data, password)


class AppPublicKey(BaseKey):
    def __init__(self, key: PublicKey, *args, **kwargs):
        super().__init__(*args, **kwargs)
        metadata = {
            "type": "CB_PUB_KEY",
            "name": self.meta.name,
            "email": self.meta.email,
        }
        data = divide_in_chunks(key.encode(), self.meta.chunksize)
        key_data = add_meta(metadata, data, DELIMITER, ESCAPE_SEQUENCE)
        self.key = key
        self.data = key_data
        self.packed = b"".join(key_data)

    def __repr__(self):
        return f"<PublicKey {self.meta.name} {self.meta.email}>"

    def __str__(self):
        return f"<PublicKey {self.meta.name} {self.meta.email}>"

    def save(self, file: Path) -> None:
        if file.exists():
            raise FileExistsError("File already exists")
        write_chunks(self.data, file)

    @classmethod
    def from_data(cls, packed: bytes) -> "AppPublicKey":
        meta, data = parse_data(packed, DELIMITER, ESCAPE_SEQUENCE)
        public_key = PublicKey(data)
        return AppPublicKey(public_key, meta["name"], meta["email"])

    @classmethod
    def from_file(cls, file: Path) -> "AppPublicKey":
        if not (file.exists() or file.is_file()):
            raise FileNotFoundError("File does not exist")
        data = file.read_bytes()
        return cls.from_data(data)
