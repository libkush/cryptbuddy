from pathlib import Path

from rich.progress import Progress

from cryptbuddy.config import DELIMITER, ESCAPE_SEQUENCE
from cryptbuddy.exceptions import DecryptionError, EncryptionError
from cryptbuddy.functions.file_data import add_meta, parse_data
from cryptbuddy.functions.file_io import shred, tar_directory, write_chunks
from cryptbuddy.functions.symmetric import decrypt_data, encrypt_data
from cryptbuddy.operations.logger import error
from cryptbuddy.structs.types import SymmetricDecryptOptions, SymmetricEncryptOptions


def symmetric_encrypt(
    path: Path,
    options: SymmetricEncryptOptions,
    output: Path,
    progress: Progress = None,
) -> None:
    """
    Encrypts the given file or folder symmetrically.

    ### Parameters
    - `path` (`Path`): The path to the file or folder to be encrypted.
    - `options` (`SymmetricEncryptOptions`): The options for encryption.
    - `output` (`Path`): The path to the output file.

    ### Raises
    - `FileNotFoundError`: If the file or folder does not exist.
    """
    if not path.exists():
        raise FileNotFoundError("File or folder does not exist")

    to_shred = options.shred
    meta = {
        "type": options.type,
        "nonce": options.nonce,
        "salt": options.salt,
        "ops": options.ops,
        "mem": options.mem,
        "chunksize": options.chunksize,
        "macsize": options.macsize,
        "keysize": options.keysize,
    }

    # create a tar archive if path is a directory
    if path.is_dir():
        original = path
        path = tar_directory(path)
        shred(original) if options.shred else None
        to_shred = True

    file_data = path.read_bytes()

    task = (
        progress.add_task(f"[cyan]Encrypting: {path.name}", total=len(file_data))
        if progress
        else None
    )

    try:
        # encrypt the file data
        encrypted_data = encrypt_data(
            file_data,
            options.key,
            options.nonce,
            options.chunksize,
            options.macsize,
            progress,
            task,
        )
    except EncryptionError as e:
        err = EncryptionError(f"Failed to encrypt file data for {path.name}")
        err.__cause__ = e
        error(err, progress, task)
        return None

    # add metadata
    encrypted_data = add_meta(
        meta,
        encrypted_data,
        DELIMITER,
        ESCAPE_SEQUENCE,
    )

    if to_shred:
        shred(path)

    write_chunks(encrypted_data, output)
    return None


def symmetric_decrypt(
    path: Path,
    options: SymmetricDecryptOptions,
    output: Path,
    progress: Progress = None,
) -> None:
    """
    Decrypts the given file or folder symmetrically.

    ### Parameters
    - `path` (`Path`): The path to the file or folder to be decrypted.
    - `options` (`SymmetricDecryptOptions`): The options for decryption.
    - `output` (`Path`): The path to the output file.

    ### Raises
    - `FileNotFoundError`: If the file or folder does not exist.
    - `ValueError`: If the file is not encrypted symmetrically.
    """
    if not path.exists():
        raise FileNotFoundError(f"{path} does not exist")

    # read the file data
    encrypted_data = path.read_bytes()

    task = (
        progress.add_task(f"[cyan]Decrypting: {path.name}", total=len(encrypted_data))
        if progress
        else None
    )

    try:
        # get the metadata
        meta, encrypted_data = parse_data(encrypted_data, DELIMITER, ESCAPE_SEQUENCE)
    except ValueError as e:
        err = ValueError(
            f"{path} is corrupt, or a different delimiter was used during encryption"
        )
        err.__cause__ = e
        error(err, progress, task)
        return None

    if meta["type"] != "symmetric":
        err = ValueError(f"{path} is not symmetrically encrypted")
        error(err, progress, task)
        return None

    ops = meta["ops"]
    mem = meta["mem"]
    salt = meta["salt"]
    nonce = meta["nonce"]
    chunksize = meta["chunksize"]
    macsize = meta["macsize"]
    keysize = meta["keysize"]

    if not (ops and mem and salt and nonce and chunksize and macsize and keysize):
        error(ValueError(f"{path} is corrupt"), progress, task)
        return None

    key = options.get_key(salt, mem, ops, keysize)

    try:
        # decrypt the file data
        decrypted_data = decrypt_data(
            encrypted_data,
            chunksize,
            key,
            nonce,
            macsize,
            progress,
            task,
        )
    except DecryptionError as e:
        err = DecryptionError(f"Failed to decrypt file data for {path.name}")
        err.__cause__ = e
        error(err, progress, task)
        return None

    if options.shred:
        shred(path)

    write_chunks(decrypted_data, output)
    return None
