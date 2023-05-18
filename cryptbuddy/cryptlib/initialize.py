from pathlib import Path

from cryptbuddy.cryptlib.file_io import *
from cryptbuddy.cryptlib.key_io import AppPrivateKey, AppPublicKey, KeyMeta
from cryptbuddy.cryptlib.keychain import Keychain
from nacl.public import PrivateKey


def initialize_cryptbuddy(name: str, email: str, password: str):
    """
    Initializes the CryptBuddy application by creating user directories and generating keypairs.

    This function initializes the CryptBuddy application by creating the necessary user directories,
    generating keypairs using NaCl, and saving the private and public keys to files. It also adds the
    public key to the keychain for future use.

    Args:
        name (str): The name associated with the user.
        email (str): The email address associated with the user.
        password (str): The password used to encrypt the private key.

    Raises:
        TypeError: If any of the arguments are not of type str.
        FileExistsError: If the private or public key files already exist.

    Note:
        The private key is saved to the config directory, while the public key is saved to the data directory.

    """

    # Create user directories if they don't exist
    create_directories()

    # Keypair will be stored in config directory
    print("Keys will be stored at: ", config_dir)
    print("Keychain is at: ", data_dir)
    print("Cache is at: ", cache_dir)

    # Check for correct argument values
    if not (isinstance(name, str) or isinstance(email, str) or isinstance(password, str)):
        raise TypeError("Invalid argument types")

    # Check if keys already exist
    if Path(f"{config_dir}/private.key").exists():
        raise FileExistsError("Private key already exists")
    if Path(f"{config_dir}/public.key").exists():
        raise FileExistsError("Public key already exists")

    # Generate keypair using NaCl
    private_key_generated = PrivateKey.generate()
    public_key_generated = private_key_generated.public_key

    # Create keypair objects
    meta = KeyMeta(name, email)
    private_key = AppPrivateKey.from_original_key(
        meta, private_key_generated, password)
    public_key = AppPublicKey(meta, public_key_generated.encode())

    # Save keys to files
    private_key.save(Path(f"{config_dir}/private.key"))
    public_key.save(Path(f"{config_dir}/public.key"))

    # Initialize and add public key to keychain
    chain = Keychain()
    chain.add_key(name, public_key.packed)
