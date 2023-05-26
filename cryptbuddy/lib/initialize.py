from pathlib import Path

from nacl.public import PrivateKey

from cryptbuddy.lib.file_io import *
from cryptbuddy.lib.key_io import AppPrivateKey, AppPublicKey, KeyMeta
from cryptbuddy.lib.keychain import Keychain
from cryptbuddy.lib.utils import *


def initialize_cryptbuddy(name: str, email: str, password: str) -> None:
    """
    Initializes CryptBuddy by generating a keypair and saving the keys.

    Parameters
    ----------
    name : `str`
        Name associated with the keypair.
    email : `str`
        Email associated with the keypair.
    password : `str`
        Password to encrypt the private key.

    Returns
    -------
    `None`

    Raises
    ------
    `TypeError`
        If any of the arguments `name`, `email`, or `password` is not a string.
    `FileExistsError`
        If the private or public key files already exist.

    Notes
    -----
    - The generated private and public keys are saved to the configuration directory.
    - The public key is added to the keychain for future use.

    """

    create_directories()

    info("Keys will be stored at: ", config_dir)
    info("Keychain is at: ", data_dir)
    info("Cache is at: ", cache_dir)

    if not (
        isinstance(name, str) or isinstance(email, str) or isinstance(password, str)
    ):
        raise TypeError("Invalid argument types")

    if Path(f"{config_dir}/private.key").exists():
        raise FileExistsError(
            "Private key already exists. You might have already initialized CryptBuddy."
        )
    if Path(f"{config_dir}/public.key").exists():
        raise FileExistsError(
            "Public key already exists. You might have already initialized CryptBuddy."
        )

    # Generate keypair using NaCl
    info("Generating keypair...")
    private_key_generated = PrivateKey.generate()
    public_key_generated = private_key_generated.public_key

    # Create keypair objects
    meta = KeyMeta(name, email)
    private_key = AppPrivateKey.from_original_key(meta, private_key_generated, password)
    public_key = AppPublicKey(meta, public_key_generated.encode())

    # Save keys to files
    private_key.save(Path(f"{config_dir}/private.key"))
    public_key.save(Path(f"{config_dir}/public.key"))
    success("Saved keys to config directory")

    # Initialize and add public key to keychain
    info("Initializing keychain...")
    chain = Keychain()
    chain.add_key(public_key)
    success("Saved your public key to the keychain")
