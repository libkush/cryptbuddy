from pathlib import Path

from nacl.public import PrivateKey
from rich.progress import Progress

from cryptbuddy.config import DATA_DIR
from cryptbuddy.operations.logging import info, success
from cryptbuddy.structs.app_keys import AppPrivateKey, AppPublicKey
from cryptbuddy.structs.keychain import Keychain


def initialize(name: str, email: str, password: str, progress: Progress | None = None):
    """
    Initializes CryptBuddy by generating a key-pair and saving it to the data directory.
    It also creates a keychain and adds the public key to it.

    ### Parameters
    - `name` (`str`): The name to be associated with the key-pair.
    - `email` (`str`): The email to be associated with the key-pair.
    - `password` (`str`): The password to be used to encrypt the private key.

    ### Raises
    - `FileExistsError`: If the key-pair already exists.
    """

    info("Key-pair will be stored at: ", DATA_DIR)

    task_id = progress.add_task("Initializing CryptBuddy", 3)

    private_key_file = Path(f"{DATA_DIR}/private.key")
    public_key_file = Path(f"{DATA_DIR}/public.key")

    if private_key_file.exists() or public_key_file.exists():
        raise FileExistsError(
            "Key-pair already exists. You might have already initialized CryptBuddy."
        )

    private_key_obj = PrivateKey.generate()
    public_key_obj = private_key_obj.public_key
    progress.update(task_id, description="Key-pair generated\n")

    private_key = AppPrivateKey(private_key_obj, password, name=name, email=email)
    public_key = AppPublicKey(public_key_obj, name=name, email=email)
    private_key.save(private_key_file)
    public_key.save(public_key_file)
    progress.update(task_id, description="Key-pair saved\n")

    keychain = Keychain()
    keychain.add_key(public_key)
    keychain.close()
    progress.update(task_id, description="Keychain created\n")

    progress.stop()

    success("CryptBuddy initialized successfully.")
