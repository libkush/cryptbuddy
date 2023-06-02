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
)
from cryptbuddy.exceptions import DecryptionError, EncryptionError
from cryptbuddy.functions.file_data import add_meta, divide_in_chunks, parse_data
from cryptbuddy.functions.file_io import shred, write_bytes, write_chunks
from cryptbuddy.functions.symmetric import decrypt_data, encrypt_data


class KeyMeta:
    """
    Metadata for a key.

    ### Parameters
    - `name` (`str`): The name of the user.
    - `email` (`str`): The email of the user.
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
    """
    Base class for keys.
    """

    def __init__(self, name: str, email: str):
        self.meta = KeyMeta(name, email)


class AppPrivateKey(BaseKey):
    """
    A private key for the application.

    ### Parameters
    - `key` (`PrivateKey`): The private key.
    - `password` (`str`): The password to encrypt the key with.
    - `name` (`str`): The name of the user.
    - `email` (`str`): The email of the user.

    ### Raises
    - `FileExistsError`: If the file already exists.

    ### Attributes
    - `data` (`bytes`): The encrypted key data.
    - `meta` (`KeyMeta`): The metadata of the encrypted key.

    ### Methods
    - `save(path: Path)`: Save the key to a file.
    - `decrypt_key(key: AppPrivateKey, password: str)`: Decrypt an AppPrivateKey instance.
    - `decrypted_key(password: str)`: Return a decrypted AppPrivateKey instance.
    - `from_data(data: bytes, password: str)`: Create an AppPrivateKey instance from encrypted data.
    - `from_file(path: Path, password: str)`: Create an AppPrivateKey instance from a private key file.


    ### Example
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

    ### Notes
    - The key is symmetrically encrypted using the password.

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
        """
        Save the key to a file.

        ### Parameters
        - `path` (`Path`): The path to save the key to.

        ### Raises
        - `FileExistsError`: If the file already exists.
        """
        if path.exists():
            raise FileExistsError("File already exists")
        write_bytes(self.data, path)

    @classmethod
    def decrypt_key(cls, data: bytes, password: str):
        """
        Decrypt an instance of `AppPrivateKey`.

        ### Parameters
        - `data` (`bytes`): The encrypted key data.
        - `password` (`str`): The password to decrypt the key with.

        ### Returns
        - `PrivateKey`: The decrypted private key.
        - `dict`: The metadata of the key.

        ### Raises
        - `DecryptionError`: If the key could not be decrypted.
        - `ValueError`: If the key type is invalid.
        """
        meta, data = parse_data(data, DELIMITER, ESCAPE_SEQUENCE)
        if not meta["type"] == "CB_PRI_KEY":
            raise ValueError("Invalid key type")
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
        """
        Get decrypted key.

        ### Parameters
        - `password` (`str`): The password to decrypt the key with.

        ### Returns
        - `PrivateKey`: The decrypted private key.

        ### Raises
        - `DecryptionError`: If the key could not be decrypted.
        """
        private_key, _meta = self.decrypt_key(self.data, password)
        return private_key

    @classmethod
    def from_data(cls, packed: bytes, password: str) -> "AppPrivateKey":
        """
        Create an instance of `AppPrivateKey` from encrypted data.

        ### Parameters
        - `packed` (`bytes`): The encrypted key data.
        - `password` (`str`): The password to decrypt the key with.

        ### Returns
        - `AppPrivateKey`: The decrypted private key.

        ### Raises
        - `DecryptionError`: If the key could not be decrypted.
        """

        decrypted_key, meta = cls.decrypt_key(packed, password)
        return AppPrivateKey(
            decrypted_key, password, name=meta["name"], email=meta["email"]
        )

    @classmethod
    def from_file(cls, file: Path, password: str) -> "AppPrivateKey":
        """
        Create an instance of `AppPrivateKey` from a file.

        ### Parameters
        - `file` (`Path`): The path to the encrypted key file.
        - `password` (`str`): The password to decrypt the key with.

        ### Returns
        - `AppPrivateKey`: The decrypted private key.

        ### Raises
        - `FileNotFoundError`: If the file does not exist.
        - `DecryptionError`: If the key could not be decrypted.
        """

        if not (file.exists() or file.is_file()):
            raise FileNotFoundError("File does not exist")
        data = file.read_bytes()
        return cls.from_data(data, password)


class AppPublicKey(BaseKey):
    def __init__(self, key: PublicKey, *args, **kwargs):
        """
        Create an instance of `AppPublicKey`.

        ### Parameters
        - `key` (`PublicKey`): The public key to encrypt.
        - `name` (`str`): The name of the key owner.

        ### Attributes
        - 'key' (`PublicKey`): The public key.
        - `data` (`List[bytes]`): The encrypted key data.
        - `meta` (`AppKeyMeta`): The metadata of the key.
        - `packed` (`bytes`): The packed key data.

        ### Methods
        - `save(path: Path)`: Save the key to a file.
        - `from_data(packed: bytes)`: Create an instance of `AppPublicKey` from packed data.
        - `from_file(file: Path)`: Create an instance of `AppPublicKey` from a file.

        ### Raises
        - `ValueError`: If the key is not a `PublicKey` instance.

        ### Notes
        - The key is not encrypted, but metadata is added to the key data.

        ### Example
        ```python
        from pathlib import Path
        from cryptbuddy.utils.app_keys import AppPublicKey, PublicKey

        key = PrivateKey.generate()
        public_key = key.public_key()

        app_public_key = AppPublicKey(public_key, name="John Doe", email="john@example.com")
        app_public_key.save(Path("public_key.cryptbuddy"))
        """
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
        """
        Save the key to a file.

        ### Parameters
        - `file` (`Path`): The path to save the key to.

        ### Raises
        - `FileExistsError`: If the file already exists.
        """
        if file.exists():
            raise FileExistsError("File already exists")
        write_chunks(self.data, file)

    @classmethod
    def from_data(cls, packed: bytes) -> "AppPublicKey":
        """
        Create an instance of `AppPublicKey` from packeddata.

        ### Parameters
        - `packed` (`bytes`): The packed key data.

        ### Returns
        - `AppPublicKey`: The public key.

        ### Raises
        - `ValueError`: If the key is not a `PublicKey` instance.
        """
        meta, data = parse_data(packed, DELIMITER, ESCAPE_SEQUENCE)
        if meta["type"] != "CB_PUB_KEY":
            raise ValueError("Invalid key type")
        public_key = PublicKey(data)
        return AppPublicKey(public_key, meta["name"], meta["email"])

    @classmethod
    def from_file(cls, file: Path) -> "AppPublicKey":
        """
        Create an instance of `AppPublicKey` from a file.

        ### Parameters
        - `file` (`Path`): The path to the key file.

        ### Returns
        - `AppPublicKey`: The public key.

        ### Raises
        - `FileNotFoundError`: If the file does not exist.

        ### Notes
        - The key is not encrypted, but metadata is added to the key data.
        """
        if not (file.exists() or file.is_file()):
            raise FileNotFoundError("File does not exist")
        data = file.read_bytes()
        return cls.from_data(data)
