from pathlib import Path

from msgpack import dumps, loads
from nacl.public import PrivateKey

from cryptbuddy.lib.file_io import *
from cryptbuddy.lib.symmetric.decrypt import symmetric_decrypt
from cryptbuddy.lib.symmetric.encrypt import symmetric_encrypt


class KeyMeta:
    """
    Metadata associated with a CryptBuddy key.

    Parameters
    ----------
    name : `str`
        Name associated with the key.
    email : `str`
        Email associated with the key.

    Attributes
    ----------
    name : `str`
        Name associated with the key.
    email : `str`
        Email associated with the key.

    """

    def __init__(self, name: str, email: str):
        self.name = name
        self.email = email


class BaseKey:
    """
    Base class for CryptBuddy keys.

    Parameters
    ----------
    meta : `KeyMeta`
        Metadata associated with the key.

    Attributes
    ----------
    meta : `KeyMeta`
        Metadata associated with the key.

    """

    def __init__(self, meta: KeyMeta):
        self.meta = meta


class AppPrivateKey(BaseKey):
    """
    Application-specific private key in CryptBuddy.

    Parameters
    ----------
    meta : `KeyMeta`
        Metadata associated with the private key.
    chunks : `List[bytes]`
        Encrypted chunks of the private key.

    Attributes
    ----------
    meta : `KeyMeta`
        Metadata associated with the private key.
    chunks : `List[bytes]`
        Encrypted chunks of the private key.
    data : `dict`
        Data dictionary representing the private key.
    packed : `bytes`
        Packed representation of the private key.

    Methods
    -------
    save(path: `Path`) -> `None`
        Save the private key to a file.
    decrypted_key_chunks(password: `str`) -> `List[bytes]`
        Decrypt and retrieve the encrypted chunks of the private key.
    decrypted_key(password: `str`) -> `PrivateKey`
        Decrypt and retrieve the NaCl private key.

    Class Methods
    -------------
    from_original_key(meta: `KeyMeta`, key: `PrivateKey`, password: `str`) -> `AppPrivateKey`:
        Create an AppPrivateKey instance from an original PrivateKey.
    from_packed(packed: `bytes`) -> `AppPrivateKey`:
        Create an AppPrivateKey instance from a packed representation.
    from_file(file: `Path`) -> `AppPrivateKey`:
        Create an AppPrivateKey instance from a key file.

    """

    def __init__(self, meta: KeyMeta, chunks: List[bytes]):
        super().__init__(meta)
        self.chunks = chunks
        self.data = {
            "type": "private",
            "name": meta.name,
            "email": meta.email,
            "chunks": chunks,
        }
        self.packed: bytes = dumps(self.data)

    def __repr__(self):
        return f"<PrivateKey {self.meta.name} {self.meta.email}>"

    def __str__(self):
        return f"<PrivateKey {self.meta.name} {self.meta.email}>"

    def save(self, path: Path):
        """
        Save the private key to a file.

        Parameters
        ----------
        path : `Path`
            The path to the file where the private key will be saved.

        Raises
        ------
        `FileExistsError`
            If the file already exists.
        """
        if path.exists():
            raise FileExistsError("File already exists")
        with open(path, "wb") as file:
            file.write(self.packed)

    @classmethod
    def from_original_key(
        cls, meta: KeyMeta, key: PrivateKey, password: str
    ) -> "AppPrivateKey":
        """
        Create an AppPrivateKey instance from an original NaCl PrivateKey.

        Parameters
        ----------
        meta : `KeyMeta`
            Metadata associated with the private key.
        key : `PrivateKey`
            NaCl PrivateKey object.
        password : `str`
            Password to encrypt the private key.

        Returns
        -------
        `AppPrivateKey`
            An AppPrivateKey instance.

        """
        temp_file = Path(f"{cache_dir}/private.key")
        write_bytes(key.encode(), temp_file)
        chunks = symmetric_encrypt(temp_file, password=password)
        shred_file(temp_file)
        return AppPrivateKey(meta, chunks)

    @classmethod
    def from_packed(cls, packed: bytes) -> "AppPrivateKey":
        """
        Create an AppPrivateKey instance from a packed representation.

        Parameters
        ----------
        packed : `bytes`
            Packed bytes of the private key data.

        Returns
        -------
        `AppPrivateKey`
            An AppPrivateKey instance.

        """
        data = loads(packed)
        meta = KeyMeta(data["name"], data["email"])
        return AppPrivateKey(meta, data["chunks"])

    @classmethod
    def from_file(cls, file: Path) -> "AppPrivateKey":
        """
        Create an AppPrivateKey instance from a file.

        Parameters
        ----------
        file : `Path`
            Path to the file containing the packed private key.

        Returns
        -------
        `AppPrivateKey`
            An AppPrivateKey instance.

        Raises
        ------
        `FileNotFoundError`
            If the file does not exist.

        """
        if not (file.exists() or file.is_file()):
            raise FileNotFoundError("File does not exist")
        with open(file, "rb") as file:
            encoded_bytes = file.read()
        return AppPrivateKey.from_packed(encoded_bytes)

    def decrypted_key_chunks(self, password: str) -> List[bytes]:
        """
        Decrypt and retrieve the decrypted chunks of the private key.

        Parameters
        ----------
        password : `str`
            Password to decrypt the private key.

        Returns
        -------
        `List[bytes]`
            Decrypted chunks of the private key.

        """
        temp_file = Path(f"{cache_dir}/private.key.crypt")
        write_chunks(self.chunks, temp_file)
        chunks = symmetric_decrypt(temp_file, password)
        shred_file(temp_file)
        return chunks

    def decrypted_key(self, password: str) -> PrivateKey:
        """
        Decrypt and retrieve the full private key.

        Parameters
        ----------
        password : `str`
            Password to decrypt the private key.

        Returns
        -------
        `PrivateKey`
            The decrypted NaCl private key.

        """
        chunks = self.decrypted_key_chunks(password)
        return PrivateKey(b"".join(chunks))


class AppPublicKey(BaseKey):
    """
    Application-specific public key in CryptBuddy.

    Parameters
    ----------
    meta : `KeyMeta`
        Metadata associated with the public key.
    key : `bytes`
        Public key bytes.

    Attributes
    ----------
    meta : `KeyMeta`
        Metadata associated with the public key.
    key : `bytes`
        Public key bytes.
    data : `dict`
        Data dictionary representing the public key.
    packed : `bytes`
        Packed bytes of the public key data.

    Methods
    -------
    save(file: `Path`)
        Save the public key to a file.

    Class Methods
    -------------
    from_packed(packed: `bytes`) -> "AppPublicKey":
        Create an AppPublicKey instance from a packed representation.
    from_file(file: `Path`) -> "AppPublicKey":
        Create an AppPublicKey instance from a file.

    """

    def __init__(self, meta: KeyMeta, key: bytes):
        super().__init__(meta)
        self.key: bytes = key
        self.data = {
            "type": "public",
            "name": meta.name,
            "email": meta.email,
            "key": key,
        }
        self.packed: bytes = dumps(self.data)

    def __repr__(self):
        return f"<PublicKey {self.meta.name} {self.meta.email}>"

    def __str__(self):
        return f"<PublicKey {self.meta.name} {self.meta.email}>"

    def save(self, file: Path) -> None:
        """
        Save the public key to a file.

        Parameters
        ----------
        file : `Path`
            The path to the file where the public key will be saved.

        Raises
        ------
        `FileExistsError`
            If the file already exists.
        """
        if file.exists():
            raise FileExistsError("File already exists")
        with open(file, "wb") as file:
            file.write(self.packed)

    @classmethod
    def from_packed(cls, packed: bytes) -> "AppPublicKey":
        """
        Create an AppPublicKey instance from a packed representation.

        Parameters
        ----------
        packed : `bytes`
            Packed data of the public key.

        Returns
        -------
        `AppPublicKey`
            An AppPublicKey instance.

        """
        data = loads(packed)
        meta = KeyMeta(data["name"], data["email"])
        return AppPublicKey(meta, data["key"])

    @classmethod
    def from_file(cls, file: Path) -> "AppPublicKey":
        """
        Create an AppPublicKey instance from a file.

        Parameters
        ----------
        file : `Path`
            Path to the file containing the packed public key.

        Returns
        -------
        `AppPublicKey`
            An AppPublicKey instance.

        Raises
        ------
        `FileNotFoundError`
            If the file does not exist.

        """
        if not (file.exists() or file.is_file()):
            raise FileNotFoundError("File does not exist")
        with open(file, "rb") as file:
            encoded_bytes = file.read()
        return AppPublicKey.from_packed(encoded_bytes)
