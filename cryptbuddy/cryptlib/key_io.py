from pathlib import Path

from cryptbuddy.cryptlib.file_io import *
from cryptbuddy.cryptlib.symmetric.decrypt import symmetric_decrypt
from cryptbuddy.cryptlib.symmetric.encrypt import symmetric_encrypt
from msgpack import dumps, loads
from nacl.public import PrivateKey


class KeyMeta:
    """
    The metadata of a key .i.e., name and email
    of the bearer
    """

    def __init__(self, name: str, email: str):
        self.name = name
        self.email = email


class BaseKey:
    """
    The base key object
    """

    def __init__(self, meta: KeyMeta):
        self.meta = meta


class AppPrivateKey(BaseKey):
    """
    The private key object. `chunks` contain the encrypted key 
    chunks. `data` has the metadata as well as the encrypted
    key chunks. `packed` is the serialized `data` that can be 
    saved to a binary file. 
    """

    def __init__(self, meta: KeyMeta, chunks: list):
        super().__init__(meta)

        # The chunks are the encrypted key chunks
        self.chunks = chunks
        self.data = {
            "type": "private",
            "name": meta.name,
            "email": meta.email,
            "chunks": chunks
        }

        # The packed data is the data that will be saved to a file
        self.packed = dumps(self.data)

    def __repr__(self):
        return f"<PrivateKey {self.meta.name} {self.meta.email}>"

    def __str__(self):
        return f"<PrivateKey {self.meta.name} {self.meta.email}>"

    # Saves the packed data
    def save(self, path: Path):
        """
        Saves the serialized key to specified file
        """

        if path.exists():
            raise FileExistsError("File already exists")
        with open(path, "wb") as file:
            file.write(self.packed)

    @classmethod
    def from_original_key(cls, meta: KeyMeta, key: PrivateKey, password: str) -> "AppPrivateKey":
        """
        Creates a private key object from an NaCl private key
        """

        # Write the key to a temporary file
        temp_file = Path(f"{cache_dir}/private.key")
        write_bytes(key.encode(), temp_file)

        # Encrypt the key and get the chunks
        chunks = symmetric_encrypt(temp_file, password=password)

        # Shred the temporary file
        shred_file(temp_file)

        return AppPrivateKey(meta, chunks)

    @classmethod
    def from_packed(cls, packed: bytes) -> "AppPrivateKey":
        """
        Creates a private key object from serialized data
        """

        # Deserialize the data
        data = loads(packed)
        meta = KeyMeta(data["name"], data["email"])

        # Return the private key object
        return AppPrivateKey(meta, data["chunks"])

    @classmethod
    def from_file(cls, file: Path) -> "AppPrivateKey":
        """
        Gets a private key object from a binary key file
        """

        # Check if the file exists
        if not (file.exists() or file.is_file()):
            raise FileNotFoundError("File does not exist")

        # Read the file and decode the data
        with open(file, "rb") as file:
            encoded_bytes = file.read()

        # Return the private key object from serialized data
        return AppPrivateKey.from_packed(encoded_bytes)

    def decrypted_key_chunks(self, password: str):
        """
        Returns the decrypted key chunks (list of bytes)
        """

        # Write the encrypted chunks to a temporary file
        temp_file = Path(f"{cache_dir}/private.key.enc")
        write_chunks(self.chunks, temp_file)

        # Decrypt the chunks
        chunks = symmetric_decrypt(temp_file, password)

        return chunks

    def decrypted_key(self, password: str):
        """
        Returns the NaCl private key object by 
        decrypting the key chunks
        """

        # Get the decrypted key chunks
        chunks = self.decrypted_key_chunks(password)

        # Join the chunks and return the key
        return PrivateKey(b"".join(chunks))


class AppPublicKey(BaseKey):
    """
    The public key object. `key` is the NaCl public key and
    `data` has the metadata as well as the key. `packed` is
    the serialized `data` that can be saved to a binary file.
    """

    def __init__(self, meta: KeyMeta, key: bytes):
        super().__init__(meta)

        # The key is an encoded NaCl public key
        self.key = key
        self.data = {
            "type": "public",
            "name": meta.name,
            "email": meta.email,
            "key": key
        }

        # The packed data is the data that will be saved to a file
        self.packed = dumps(self.data)

    def __repr__(self):
        return f"<PublicKey {self.meta.name} {self.meta.email}>"

    def __str__(self):
        return f"<PublicKey {self.meta.name} {self.meta.email}>"

    # Saves the serialized data to a file
    def save(self, file: Path):
        if file.exists():
            raise FileExistsError("File already exists")
        with open(file, "wb") as file:
            file.write(self.packed)

    @classmethod
    def from_packed(cls, packed: bytes) -> "AppPublicKey":
        """
        Creates a public key object from serialized data
        """

        data = loads(packed)
        meta = KeyMeta(data["name"], data["email"])

        # Return the public key object
        return AppPublicKey(meta, data["key"])

    @classmethod
    def from_file(cls, file: Path) -> "AppPublicKey":
        """
        Gets a public key object from a binary key file
        """

        # Check if file exists
        if not (file.exists() or file.is_file()):
            raise FileNotFoundError("File does not exist")

        # Read the file and decode the data
        with open(file, "rb") as file:
            encoded_bytes = file.read()

        # Return the public key object from serialized data
        return AppPublicKey.from_packed(encoded_bytes)
