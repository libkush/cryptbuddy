from pathlib import Path

from nacl.public import PrivateKey
from rich.progress import Progress

from cryptbuddy.config import DATA_DIR
from cryptbuddy.operations.logger import error, info, success
from cryptbuddy.structs.app_keys import AppPrivateKey, AppPublicKey
from cryptbuddy.structs.keychain import Keychain


def initialize(name: str, email: str, password: str, progress: Progress):
    """
    Initializes CryptBuddy by generating a key-pair and saving it to the data directory.
    It also creates a keychain and adds the public key to it.

    Parameters
    ----------
    name : str
        The name to be associated with the key-pair.
    email : str
        The email to be associated with the key-pair.
    password : str
        The password to be used to encrypt the private key.
    progress: rich.progress.Progress, optional
        Rich progressbar.
    """
    info("Key-pair will be stored at: ", DATA_DIR, console=progress.console)
    task = progress.add_task("Initializing CryptBuddy", total=3)

    private_key_file = Path(f"{DATA_DIR}/private.key")
    public_key_file = Path(f"{DATA_DIR}/public.key")

    if private_key_file.exists() or public_key_file.exists():
        err = FileExistsError(
            "Key-pair already exists. You might have already initialized CryptBuddy."
        )
        return error(err, progress.console)

    private_key_obj = PrivateKey.generate()
    public_key_obj = private_key_obj.public_key
    progress.update(task, description="Key-pair generated\n", completed=1)

    private_key = AppPrivateKey(private_key_obj, password, name=name, email=email)
    public_key = AppPublicKey(public_key_obj, name=name, email=email)
    private_key.save(private_key_file)
    public_key.save(public_key_file)
    progress.update(task, description="Key-pair saved\n", completed=2)

    keychain = Keychain()
    keychain.add_key(public_key)
    keychain.close()
    progress.update(task, description="Keychain created\n", completed=3)
    return success("CryptBuddy initialized..", console=progress.console)
