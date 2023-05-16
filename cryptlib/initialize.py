from pathlib import Path
from nacl.public import PrivateKey
from cryptlib.file_io import Directories
from cryptlib.key_io import AppPrivateKey, AppPublicKey, KeyMeta
from cryptlib.keychain import keychain


def initialize_cryptbuddy(name: str, email: str, password: str):
    """Initializes CryptBuddy"""

    # Create user directories if they don't exist
    Directories.create_directories()

    # Keypair will be stored in config directory
    dir = Directories().config_dir
    print("Keys will be stored at: ", dir)
    print("Keychain is at: ", Directories().data_dir)
    print("Cache is at: ", Directories().cache_dir)

    # Check for correct argument values
    if not (isinstance(name, str) or isinstance(email, str) or isinstance(password, str)):
        raise TypeError("Invalid argument types")

    # Check if keys already exist
    if Path(f"{dir}/private.key").exists():
        raise FileExistsError("Private key already exists")
    if Path(f"{dir}/public.key").exists():
        raise FileExistsError("Public key already exists")

    # Generate keypair using NaCl
    private_key_generated = PrivateKey.generate()
    public_key_generated = private_key_generated.public_key

    # Create keypair objects
    meta = KeyMeta(name, email)
    private_key = AppPrivateKey.from_original_key(
        meta, private_key_generated.encode(), password)
    public_key = AppPublicKey(meta, public_key_generated.encode())

    # Save keys to files
    private_key.save(Path(f"{dir}/private.key"))
    public_key.save(Path(f"{dir}/public.key"))

    # Initialize and add public key to keychain
    chain = keychain()
    chain.add_key(name, public_key.packed)
