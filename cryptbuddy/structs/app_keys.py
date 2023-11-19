import io
from pathlib import Path

import msgpack
from nacl.public import PrivateKey, PublicKey
from nacl.pwhash.argon2i import kdf
from nacl.secret import SecretBox
from nacl.utils import random

from cryptbuddy.constants import (
    CHUNKSIZE,
    INTSIZE,
    KEYSIZE,
    MACSIZE,
    MAGICNUM,
    MEM,
    NONCESIZE,
    OPS,
    SALTBYTES,
)
from cryptbuddy.functions.file_ops import extract_metadata
from cryptbuddy.functions.symmetric import decrypt_chunk, encrypt_chunk


class KeyMeta:
    """
    Metadata for a key.

    Parameters
    ----------
    name : str
        The name of the user.
    email : str
        The email of the user.
    """

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
    """Base class for keys."""

    def __init__(self, name: str, email: str):
        self.meta = KeyMeta(name, email)


class AppPrivateKey(BaseKey):
    """
    A private key for the application.

    Parameters
    ----------
    key : nacl.public.PrivateKey
        The private key.
    password : str
        The password to encrypt the key with.
    name : str
        The name of the user.
    email : str
        The email of the user.

    Attributes
    ----------
    data : bytes
        The encrypted key data.
    meta : KeyMeta
        The metadata of the encrypted key.

    Methods
    -------
    save(path: pathlib.Path)
        Save the key to a file.
    decrypt_key(data: bytes, password: str)
        Decrypt an AppPrivateKey's data.
    decrypted_key(password: str)
        Return a decrypted
        AppPrivateKey instance.
    from_data(data: bytes, password: str)
        Create an AppPrivateKey
        instance from encrypted data.
    from_file(path: pathlib.Path, password: str)
        Create an AppPrivateKey
        instance from a private key file.


    Example
    -------
    ```py
    from cryptbuddy.structs.app_keys import AppPrivateKey
    from cryptbuddy.functions.file_io import write_bytes
    from nacl.public import PrivateKey

    key = AppPrivateKey(
        PrivateKey.generate(),
        password="randompassword",
        name="John Doe",
        email="john@example.com"
    )
    key.save("key.cryptbuddy")
    ```
    """

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
        meta: bytes = msgpack.packb(metadata)  # type: ignore
        metasize = len(meta).to_bytes(
            INTSIZE,
            "big",
        )
        data = MAGICNUM + metasize + meta
        symkey = kdf(
            self.meta.keysize,
            password.encode(),
            salt,
            self.meta.ops,
            self.meta.mem,
        )
        secret_box = SecretBox(symkey)
        encrypted_data = encrypt_chunk((key.encode(), secret_box, nonce))
        data += encrypted_data
        self.data = data

    def __repr__(self):
        return f"<PrivateKey {self.meta.name} {self.meta.email}>"

    def __str__(self):
        return f"<PrivateKey {self.meta.name} {self.meta.email}>"

    def save(self, path: Path):
        """
        Save the key to a file.

        Parameters
        ----------
        path : pathlib.Path
            The path to save the key to.
        """
        if path.exists():
            raise FileExistsError("File already exists")
        path.write_bytes(self.data)

    @classmethod
    def decrypt_key(cls, data: bytes, password: str):
        """
        Decrypt an instance of `AppPrivateKey`.

        Parameters
        ----------
        data : bytes
            The encrypted key data.
        password : str
            The password to decrypt the key with.

        Returns
        -------
        nacl.public.PrivateKey
            The decrypted private key.
        dict
            The metadata of the key.
        """
        dataIO = io.BytesIO(data)
        metadata = extract_metadata(dataIO, MAGICNUM, INTSIZE)
        if not metadata["type"] == "CB_PRI_KEY":
            raise ValueError("Invalid key type")
        symkey = kdf(
            size=metadata["keysize"],
            password=password.encode(),
            salt=metadata["salt"],
            opslimit=metadata["ops"],
            memlimit=metadata["mem"],
        )
        secret_box = SecretBox(symkey)
        ciphertext = dataIO.read()
        decrypted_data = decrypt_chunk((ciphertext, secret_box, metadata["nonce"]))
        private_key = PrivateKey(decrypted_data)
        return private_key, metadata

    def decrypted_key(self, password: str) -> PrivateKey:
        """
        Get decrypted key.

        Parameters
        ----------
        password : str
            The password to decrypt the key with.

        Returns
        -------
        PrivateKey
            The decrypted private key.
        """
        private_key, _meta = self.decrypt_key(self.data, password)
        return private_key

    @classmethod
    def from_data(cls, data: bytes, password: str) -> "AppPrivateKey":
        """
        Create an instance of `AppPrivateKey` from encrypted data.

        Parameters
        ----------
        packed : bytes
            The encrypted key data.
        password : str
            The password to decrypt the key with.

        Returns
        -------
        AppPrivateKey
            The decrypted private key.
        """
        decrypted_key, meta = cls.decrypt_key(data, password)
        return AppPrivateKey(
            decrypted_key, password, name=meta["name"], email=meta["email"]
        )

    @classmethod
    def from_file(cls, file: Path, password: str) -> "AppPrivateKey":
        """
        Create an instance of `AppPrivateKey` from a file.

        Parameters
        ----------
        file : pathlib.Path
            The path to the encrypted key file.
        password : str
            The password to decrypt the key with.

        Returns
        -------
        AppPrivateKey
            The decrypted private key.
        """
        if not (file.exists() or file.is_file()):
            raise FileNotFoundError("File does not exist")
        data = file.read_bytes()
        return cls.from_data(data, password)


class AppPublicKey(BaseKey):
    """
    Create an instance of `AppPublicKey`.

    Parameters
    ----------
    key : nacl.public.PublicKey
        The public key to encrypt.
    name : str
        The name of the key owner.
    email : str
        The email of the key owner.

    Attributes
    ----------
    key : nacl.public.PublicKey
        The public key.
    data : List[bytes]
        The encrypted key data.
    meta : AppKeyMeta
        The metadata of the key.
    packed : bytes
        The packed key data.

    Methods
    -------
    save(path: pathlib.Path)
        Save the key to a file.
    from_data(packed: bytes)
        Create an instance of `AppPublicKey` from packed data.
    from_file(file: pathlib.Path)
        Create an instance of `AppPublicKey` from a file.

    Example
    -------
    ```python
    from pathlib import Path
    from cryptbuddy.utils.app_keys import AppPublicKey, PublicKey

    key = PrivateKey.generate()
    public_key = key.public_key()

    app_public_key = AppPublicKey(
        public_key,
        name="John Doe",
        email="john@example.com"
    )
    app_public_key.save(Path("public_key.cryptbuddy"))
    ```
    """

    def __init__(self, key: PublicKey, *args, **kwargs):
        super().__init__(*args, **kwargs)
        metadata = {
            "type": "CB_PUB_KEY",
            "name": self.meta.name,
            "email": self.meta.email,
        }
        self.key = key
        meta: bytes = msgpack.packb(metadata)  # type: ignore
        metasize = len(meta).to_bytes(
            INTSIZE,
            "big",
        )
        self.data = MAGICNUM + metasize + meta + key.encode()

    def __repr__(self):
        return f"<PublicKey {self.meta.name} {self.meta.email}>"

    def __str__(self):
        return f"<PublicKey {self.meta.name} {self.meta.email}>"

    def save(self, path: Path) -> None:
        """
        Save the key to a file.

        Parameters
        ----------
        file : pathlib.Path
            The path to save the key to.
        """
        if path.exists():
            raise FileExistsError("File already exists")
        path.write_bytes(self.data)

    @classmethod
    def from_data(cls, data: bytes) -> "AppPublicKey":
        """
        Create an instance of `AppPublicKey` from packeddata.

        Parameters
        ----------
        packed : bytes
            The packed key data.

        Returns
        -------
        AppPublicKey
            The public key.
        """
        dataIO = io.BytesIO(data)
        metadata = extract_metadata(dataIO, MAGICNUM, INTSIZE)
        if metadata["type"] != "CB_PUB_KEY":
            raise ValueError("Invalid key type")
        public_key = PublicKey(dataIO.read())
        return AppPublicKey(public_key, metadata["name"], metadata["email"])

    @classmethod
    def from_file(cls, file: Path) -> "AppPublicKey":
        """
        Create an instance of `AppPublicKey` from a file.

        Parameters
        ----------
        file : pathlib.Path
            The path to the key file.

        Returns
        -------
        AppPublicKey
            The public key.
        """
        if not (file.exists() or file.is_file()):
            raise FileNotFoundError("File does not exist")
        data = file.read_bytes()
        return cls.from_data(data)
