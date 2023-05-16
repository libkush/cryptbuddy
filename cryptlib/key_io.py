from pathlib import Path
from msgpack import dumps, loads
from cryptlib.file_io import write_chunks, shred_file, Directories, write_bytes
from cryptlib.symmetric.decrypt import symmetric_decrypt
from cryptlib.symmetric.encrypt import symmetric_encrypt
cache_dir = Directories().cache_dir


# The key metadata object
class KeyMeta:
    def __init__(self, name: str, email: str):
        self.name = name
        self.email = email


# The base key object
class BaseKey:
    def __init__(self, meta: KeyMeta):
        self.meta = meta


# The private key object
class AppPrivateKey(BaseKey):
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
        """Saves the packed key to a file"""
        if path.exists():
            raise FileExistsError("File already exists")
        with open(path, "wb") as file:
            file.write(self.packed)

    @classmethod
    def from_original_key(cls, meta: KeyMeta, key: bytes, password: str) -> "AppPrivateKey":
        """Creates a private key object from an NaCl private key"""

        # Write the key to a temporary file
        temp_file = Path(f"{cache_dir}/private.key")
        write_bytes(key, temp_file)

        # Encrypt the key and get the chunks
        chunks = symmetric_encrypt(temp_file, password)

        # Shred the temporary file
        shred_file(temp_file)

        return AppPrivateKey(meta, chunks)

    @classmethod
    def from_packed(cls, packed: bytes) -> "AppPrivateKey":
        """Creates a private key object from packed data"""
        data = loads(packed)

        # Return the private key object
        return AppPrivateKey(data["name"], data["email"], data["chunks"])

    @classmethod
    def get_from_file(cls, file: Path) -> "AppPrivateKey":
        """Gets a private key object from a file"""

        # Check if file exists
        if not (file.exists() or file.is_file()):
            raise FileNotFoundError("File does not exist")

        # Read the file and decode the data
        with open(file, "rb") as file:
            encoded_bytes = file.read()

        return AppPrivateKey.from_packed(encoded_bytes)

    def decrypted_key_chunks(self, password: str):
        """Returns the decrypted key chunks"""

        # Write the encrypted chunks to a temporary file
        temp_file = f"{cache_dir}/private.key.enc"
        write_chunks(self.chunks, temp_file)

        # Decrypt the chunks
        chunks = symmetric_decrypt(temp_file, password)

        return chunks


# The public key object
class AppPublicKey(BaseKey):
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

    # Saves the packed data
    def save(self, path: Path):
        if path.exists():
            raise FileExistsError("File already exists")
        with open(path, "wb") as file:
            file.write(self.packed)

    @classmethod
    def from_packed(cls, packed: bytes) -> "AppPublicKey":
        """Creates a public key object from packed data"""
        data = loads(packed)

        # Return the public key object
        return AppPublicKey(data["name"], data["email"], data["key"])

    @classmethod
    def get_from_file(cls, file: Path) -> "AppPublicKey":
        """Gets a public key object from a file"""

        # Check if file exists
        if not (file.exists() or file.is_file()):
            raise FileNotFoundError("File does not exist")

        # Read the file and decode the data
        with open(file, "rb") as file:
            encoded_bytes = file.read()

        return AppPublicKey.from_packed(encoded_bytes)
