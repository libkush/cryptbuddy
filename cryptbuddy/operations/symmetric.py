from pathlib import Path

from rich.progress import TaskID

from cryptbuddy.config import DELIMITER, ESCAPE_SEQUENCE
from cryptbuddy.exceptions import DecryptionError, EncryptionError
from cryptbuddy.functions.file_data import add_meta, parse_data
from cryptbuddy.functions.file_io import (
    shred,
    tar_directory,
    untar_directory,
    write_chunks,
)
from cryptbuddy.functions.symmetric import decrypt_data, encrypt_data
from cryptbuddy.operations.logger import error
from cryptbuddy.structs.options import SymmetricDecryptOptions, SymmetricEncryptOptions
from cryptbuddy.structs.types import ProgressState


def symmetric_encrypt(
    path: Path,
    options: SymmetricEncryptOptions,
    output: Path,
    progress: ProgressState = None,
    task: TaskID = None,
) -> None:
    """
    Encrypts the given file or folder symmetrically.

    ### Parameters
    - `path` (`Path`): The path to the file or folder to be encrypted.
    - `options` (`SymmetricEncryptOptions`): The options for encryption.
    - `progress` (`ProgressState`, optional): The shared progress state object.
    - `output` (`Path`): The path to the output file.

    ### Raises
    - `FileNotFoundError`: If the file or folder does not exist.
    """
    if not path.exists():
        raise FileNotFoundError("File or folder does not exist")

    to_shred = options.shred

    # create metadata
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
        if options.shred:
            shred(original)
        # original directory shredded regardless of options.shred
        to_shred = True

    file_data = path.read_bytes()

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
    except Exception as e:
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
    progress: ProgressState = None,
    task: TaskID = None,
) -> None:
    """
    Decrypts the given file or folder symmetrically.

    ### Parameters
    - `path` (`Path`): The path to the file or folder to be decrypted.
    - `options` (`SymmetricDecryptOptions`): The options for decryption.
    - `output` (`Path`): The path to the output file.
    - `progress` (`ProgressState`, optional): The shared progress state object.
    - `task` (`TaskID`, optional): The task ID for the progress bar.

    ### Raises
    - `FileNotFoundError`: If the file or folder does not exist.
    - `ValueError`: If the file is not encrypted symmetrically.
    """
    if not path.exists():
        raise FileNotFoundError(f"{path} does not exist")

    encrypted_data = path.read_bytes()

    try:
        # parse metadata and encrypted data
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

    # get required values from metadata
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

    # get the symmetric key
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
    except Exception as e:
        err = DecryptionError(f"Failed to decrypt file data for {path.name}")
        err.__cause__ = e
        error(err, progress, task)
        return None

    if options.shred:
        shred(path)

    write_chunks(decrypted_data, output)

    # untar the directory if output is a directory
    if output.suffix == ".tar":
        untar_directory(output, output.parent, options.shred)

    return None
