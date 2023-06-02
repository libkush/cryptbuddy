from pathlib import Path

from nacl.public import PrivateKey

from cryptbuddy.config import CACHE_DIR, CONFIG_DIR, DATA_DIR
from cryptbuddy.operations.logging import (
    add_task,
    error,
    info,
    start_process,
    stop_process,
    success,
    update_task,
)
from cryptbuddy.structs.app_keys import AppPrivateKey, AppPublicKey, KeyMeta
from cryptbuddy.structs.keychain import Keychain


def initialize(name: str, email: str, password: str):
    start_process()

    info("Key-pair will be stored at: ", DATA_DIR)

    task_id = add_task("Initializing CryptBuddy", 3)

    private_key_file = Path(f"{DATA_DIR}/private.key")
    public_key_file = Path(f"{DATA_DIR}/public.key")

    if private_key_file.exists() or public_key_file.exists():
        error("Key-pair already exists. You might have already initialized CryptBuddy.")
        stop_process()
        return

    private_key_obj = PrivateKey.generate()
    public_key_obj = private_key_obj.public_key
    update_task(task_id, "Key-pair generated\n")

    private_key = AppPrivateKey(private_key_obj, password, name=name, email=email)
    public_key = AppPublicKey(public_key_obj, name=name, email=email)
    private_key.save(private_key_file)
    public_key.save(public_key_file)
    update_task(task_id, "Key-pair saved\n")

    keychain = Keychain()
    keychain.add_key(public_key)
    keychain.close()
    update_task(task_id, "Keychain created\n")

    success("CryptBuddy initialized successfully.")
