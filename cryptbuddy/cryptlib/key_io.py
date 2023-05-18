from pathlib import Path

from cryptbuddy.cryptlib.file_io import *
from cryptbuddy.cryptlib.symmetric.decrypt import symmetric_decrypt
from cryptbuddy.cryptlib.symmetric.encrypt import symmetric_encrypt
from msgpack import dumps, loads
from nacl.public import PrivateKey


class KeyMeta:
    """   
    Represents metadata associated with a cryptographic key.

    This class is used to store metadata information, such as the name and email address,
    associated with a cryptographic key.

    Args:
        name (str): The name associated with the key.
        email (str): The email address associated with the key.

    Attributes:
        name (str): The name associated with the key.
        email (str): The email address associated with the key.

    """

    def __init__(self, name: str, email: str):
        self.name = name
        self.email = email


class BaseKey:
    """
    Represents a base cryptographic key.

    This class serves as the base class for cryptographic key objects. It contains the
    metadata associated with the key.

    Args:
        meta (KeyMeta): The metadata associated with the key.

    Attributes:
        meta (KeyMeta): The metadata associated with the key.

    """

    def __init__(self, meta: KeyMeta):
        self.meta = meta


class AppPrivateKey(BaseKey):
    """
    Represents an application-specific private key.

    This class extends the `BaseKey` class and provides additional functionality specific
    to private keys used in the application.

    Args:
        meta (KeyMeta): The metadata associated with the private key.
        chunks (list): The encrypted key chunks.

    Attributes:
        meta (KeyMeta): The metadata associated with the private key.
        chunks (list): The encrypted key chunks.
        data (dict): The serialized data representation of the private key.
        packed (bytes): The packed data representation of the private key.

    """

    def __init__(self, meta: KeyMeta, chunks: list):
        super().__init__(meta)
        self.chunks = chunks
        self.data = {
            "type": "private",
            "name": meta.name,
            "email": meta.email,
            "chunks": chunks
        }
        self.packed = dumps(self.data)

    def __repr__(self):
        return f"<PrivateKey {self.meta.name} {self.meta.email}>"

    def __str__(self):
        return f"<PrivateKey {self.meta.name} {self.meta.email}>"

    def save(self, path: Path):
        """
        Save the packed private key data to a file.

        Args:
            path (Path): The path to the file where the private key will be saved.

        Raises:
            FileExistsError: If the file already exists.

        """
        if path.exists():
            raise FileExistsError("File already exists")
        with open(path, "wb") as file:
            file.write(self.packed)

    @classmethod
    def from_original_key(cls, meta: KeyMeta, key: PrivateKey, password: str) -> "AppPrivateKey":
        """
        Create an `AppPrivateKey` object from an original private key.

        Args:
            meta (KeyMeta): The metadata associated with the private key.
            key (PrivateKey): The original private key.
            password (str): The password to encrypt the private key.

        Returns:
            AppPrivateKey: The created `AppPrivateKey` object.

        """
        temp_file = Path(f"{cache_dir}/private.key")
        write_bytes(key.encode(), temp_file)
        chunks = symmetric_encrypt(temp_file, password=password)
        shred_file(temp_file)
        return AppPrivateKey(meta, chunks)

    @classmethod
    def from_packed(cls, packed: bytes) -> "AppPrivateKey":
        """
        Create an `AppPrivateKey` object from packed data.

        Args:
            packed (bytes): The packed data representing the private key.

        Returns:
            AppPrivateKey: The created `AppPrivateKey` object.

        """
        data = loads(packed)
        meta = KeyMeta(data["name"], data["email"])
        return AppPrivateKey(meta, data["chunks"])

    @classmethod
    def from_file(cls, file: Path) -> "AppPrivateKey":
        """
        Create an `AppPrivateKey` object from a file.

        Args:
            file (Path): The path to the file containing the packed private key.

        Returns:
            AppPrivateKey: The created `AppPrivateKey` object.

        Raises:
            FileNotFoundError: If the file does not exist.

        """
        if not (file.exists() or file.is_file()):
            raise FileNotFoundError("File does not exist")
        with open(file, "rb") as file:
            encoded_bytes = file.read()
        return AppPrivateKey.from_packed(encoded_bytes)

    def decrypted_key_chunks(self, password: str):
        """
        Decrypt the encrypted key chunks using the provided password.

        Args:
            password (str): The password to decrypt the private key.

        Returns:
            list: The decrypted key chunks.

        """
        temp_file = Path(f"{cache_dir}/private.key.crypt")
        write_chunks(self.chunks, temp_file)
        chunks = symmetric_decrypt(temp_file, password)
        return chunks

    def decrypted_key(self, password: str):
        """
        Get the decrypted private key using the provided password.

        Args:
            password (str): The password to decrypt the private key.

        Returns:
            PrivateKey: The decrypted private key.

        """
        chunks = self.decrypted_key_chunks(password)
        return PrivateKey(b"".join(chunks))


class AppPublicKey(BaseKey):
    """
    Represents an application-specific public key.

    This class extends the `BaseKey` class and provides additional functionality specific
    to public keys used in the application.

    Args:
        meta (KeyMeta): The metadata associated with the public key.
        key (bytes): The encoded NaCl public key.

    Attributes:
        meta (KeyMeta): The metadata associated with the public key.
        key (bytes): The encoded NaCl public key.
        data (dict): The serialized data representation of the public key.
        packed (bytes): The packed data representation of the public key.

    """

    def __init__(self, meta: KeyMeta, key: bytes):
        super().__init__(meta)
        self.key = key
        self.data = {
            "type": "public",
            "name": meta.name,
            "email": meta.email,
            "key": key
        }
        self.packed = dumps(self.data)

    def __repr__(self):
        return f"<PublicKey {self.meta.name} {self.meta.email}>"

    def __str__(self):
        return f"<PublicKey {self.meta.name} {self.meta.email}>"

    def save(self, file: Path):
        """
        Save the serialized public key data to a file.

        Args:
            file (Path): The path to the file where the public key will be saved.

        Raises:
            FileExistsError: If the file already exists.

        """
        if file.exists():
            raise FileExistsError("File already exists")
        with open(file, "wb") as file:
            file.write(self.packed)

    @classmethod
    def from_packed(cls, packed: bytes) -> "AppPublicKey":
        """
        Create an `AppPublicKey` object from packed data.

        Args:
            packed (bytes): The packed data representing the public key.

        Returns:
            AppPublicKey: The created `AppPublicKey` object.

        """
        data = loads(packed)
        meta = KeyMeta(data["name"], data["email"])
        return AppPublicKey(meta, data["key"])

    @classmethod
    def from_file(cls, file: Path) -> "AppPublicKey":
        """
        Create an `AppPublicKey` object from a file.

        Args:
            file (Path): The path to the file containing the packed public key.

        Returns:
            AppPublicKey: The created `AppPublicKey` object.

        Raises:
            FileNotFoundError: If the file does not exist.

        """
        if not (file.exists() or file.is_file()):
            raise FileNotFoundError("File does not exist")
        with open(file, "rb") as file:
            encoded_bytes = file.read()
        return AppPublicKey.from_packed(encoded_bytes)
