from pathlib import Path

from rich.progress import Progress

from cryptbuddy.config import DELIMITER, ESCAPE_SEQUENCE
from cryptbuddy.exceptions import DecryptionError, EncryptionError
from cryptbuddy.functions.asymmetric import decrypt, encrypt
from cryptbuddy.functions.file_data import add_meta, parse_data
from cryptbuddy.functions.file_io import shred, tar_directory, write_chunks
from cryptbuddy.functions.symmetric import decrypt_data, encrypt_data
from cryptbuddy.operations.logger import error
from cryptbuddy.structs.types import AsymmetricDecryptOptions, AsymmetricEncryptOptions


def asymmetric_encrypt(
    path: Path,
    options: AsymmetricEncryptOptions,
    output: Path,
    progress: Progress | None = None,
) -> None:
    """
    Encrypts the given file or folder asymmetrically.

    ### Parameters
    - `path` (`Path`): The path to the file or folder to be encrypted.
    - `options` (`AsymmetricEncryptOptions`): The options for encryption.
    - `output` (`Path`): The path to the output file.
    - `progress` (`Progress`, optional): A rich progress instance.
    """
    if not path.exists():
        raise FileNotFoundError(f"{path} does not exist")

    encrypted_symkeys = {}
    to_shred = options.shred
    for key in options.public_keys:
        name = key.meta.name
        public_key = key.key
        try:
            encrypted_symkey = encrypt(public_key, options.symkey)
        except EncryptionError as e:
            raise EncryptionError(f"Failed to encrypt symmetric key for {name}") from e
        encrypted_symkeys[name] = encrypted_symkey

    meta = {
        "type": options.type,
        "encrypted_symkeys": encrypted_symkeys,
        "nonce": options.nonce,
        "chunksize": options.chunksize,
        "macsize": options.macsize,
    }

    # create a tar archive if path is a directory
    if path.is_dir():
        original = path
        path = tar_directory(path)
        shred(original) if options.shred else None
        to_shred = True

    file_data = path.read_bytes()

    task = (
        progress.add_task(f"[cyan]Encrypting... {path.name}", total=len(file_data))
        if progress
        else None
    )

    try:
        # encrypt the file data
        encrypted_data = encrypt_data(
            file_data,
            options.symkey,
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


def asymmetric_decrypt(
    path: Path,
    options: AsymmetricDecryptOptions,
    output: Path,
    progress: Progress | None = None,
) -> None:
    """
    Decrypts the given file or folder asymmetrically.

    ### Parameters
    - `path` (`Path`): The path to the file or folder to be decrypted.
    - `options` (`AsymmetricDecryptOptions`): The options for decryption.
    - `output` (`Path`): The path to the output file.
    - `progress` (`Progress`, optional): A rich progress instance.
    """
    if not path.exists():
        raise FileNotFoundError(f"{path} does not exist")

    # read the file data
    encrypted_data = path.read_bytes()

    task = (
        progress.add_task(f"[cyan]Decrypting... {path.name}", total=len(encrypted_data))
        if progress
        else None
    )

    # get the metadata
    try:
        meta, encrypted_data = parse_data(encrypted_data, DELIMITER, ESCAPE_SEQUENCE)
    except ValueError as e:
        err = ValueError(
            f"{path} is corrupt, or a different delimiter was used during encryption"
        )
        err.__cause__ = e
        error(err, progress, task)
        return None

    if not meta["type"] == "asymmetric":
        error(ValueError(f"{path} is not asymmetrically encrypted"), progress, task)
        return None

    encrypted_symkeys: dict[str, bytes] = meta["encrypted_symkeys"]
    nonce = meta["nonce"]
    macsize = meta["macsize"]
    chunksize = meta["chunksize"]

    if not (encrypted_symkeys and nonce and macsize and chunksize):
        error(ValueError(f"{path} is corrupt"), progress, task)
        return None

    try:
        private_key = options.private_key.decrypted_key(options.password)
    except DecryptionError as e:
        err = DecryptionError(f"Failed to decrypt private key for {options.user}")
        err.__cause__ = e
        error(err, progress, task)
        return None

    mykey = encrypted_symkeys[options.user]
    if not mykey:
        err = ValueError(f"{path} was not encrypted for {options.user}")
        error(err, progress, task)
        return None

    # decrypt symkey
    try:
        symkey = decrypt(private_key, mykey)
    except DecryptionError as e:
        err = DecryptionError(
            f"Failed to decrypt symmetric key for {options.user} in {path}"
        )
        err.__cause__ = e
        error(err, progress, task)
        return None

    # decrypt the file data
    try:
        file_data = decrypt_data(
            encrypted_data, chunksize, symkey, nonce, macsize, progress, task
        )
    except DecryptionError as e:
        err = DecryptionError(f"Failed to decrypt file data for {path.name}")
        err.__cause__ = e
        error(err, progress, task)
        return None

    if options.shred:
        shred(path)

    write_chunks(file_data, output)
    return None
