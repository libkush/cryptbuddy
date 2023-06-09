from pathlib import Path

from rich.progress import TaskID

from cryptbuddy.config import DELIMITER, ESCAPE_SEQUENCE
from cryptbuddy.functions.asymmetric import decrypt, encrypt
from cryptbuddy.functions.file_data import add_meta, parse_data
from cryptbuddy.functions.file_io import (
    shred,
    tar_directory,
    untar_directory,
    write_chunks,
)
from cryptbuddy.functions.symmetric import decrypt_data, encrypt_data
from cryptbuddy.operations.logger import error
from cryptbuddy.structs.exceptions import DecryptionError, EncryptionError
from cryptbuddy.structs.options import (
    AsymmetricDecryptOptions,
    AsymmetricEncryptOptions,
)
from cryptbuddy.structs.types import ProgressState


def asymmetric_encrypt(
    path: Path,
    options: AsymmetricEncryptOptions,
    output: Path,
    progress: ProgressState | None = None,
    task: TaskID | None = None,
) -> None:
    """
    Encrypts the given file or folder asymmetrically.

    ### Parameters
    - `path` (`Path`): The path to the file or folder to be encrypted.
    - `options` (`AsymmetricEncryptOptions`): The options for encryption.
    - `output` (`Path`): The path to the output file.
    - `progress` (`ProgressState`, optional): The shared progress state object.
    """
    if not path.exists():
        raise FileNotFoundError(f"{path} does not exist")

    # encrypt the symmetric key for each public key
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

    # create metadata
    meta = {
        "type": options.type,
        "encrypted_symkeys": encrypted_symkeys,
        "nonce": options.nonce,
        "chunksize": options.chunksize,
        "macsize": options.macsize,
    }

    # we will create a single tar file for a directory
    if path.is_dir():
        original = path
        path = tar_directory(path)
        if options.shred:
            shred(original)
        # original folder will be shredded regardless of options.shred
        # since it is now a tar file
        to_shred = True

    file_data = path.read_bytes()

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
    return None


def asymmetric_decrypt(
    path: Path,
    options: AsymmetricDecryptOptions,
    output: Path,
    progress: ProgressState | None = None,
    task: TaskID | None = None,
) -> None:
    """
    Decrypts the given file or folder asymmetrically.

    ### Parameters
    - `path` (`Path`): The path to the file or folder to be decrypted.
    - `options` (`AsymmetricDecryptOptions`): The options for decryption.
    - `output` (`Path`): The path to the output file.
    - `progress` (`ProgressState`, optional): The shared progress state object.
    """
    if not path.exists():
        raise FileNotFoundError(f"{path} does not exist")

    encrypted_data = path.read_bytes()

    # parse the metadata and encrypted data
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

    # get required metadata
    encrypted_symkeys: dict[str, bytes] = meta["encrypted_symkeys"]
    nonce = meta["nonce"]
    macsize = meta["macsize"]
    chunksize = meta["chunksize"]

    if not (encrypted_symkeys and nonce and macsize and chunksize):
        error(ValueError(f"{path} is corrupt"), progress, task)
        return None

    # decrypt personal private key
    try:
        private_key = options.private_key.decrypted_key(options.password)
    except DecryptionError as e:
        err = DecryptionError(f"Failed to decrypt private key for {options.user}")
        err.__cause__ = e
        error(err, progress, task)
        return None

    # get the encrypted symmetric key for this user
    mykey = encrypted_symkeys[options.user]
    if not mykey:
        err = ValueError(f"{path} was not encrypted for {options.user}")
        error(err, progress, task)
        return None

    # decrypt the symmetric key using user's private key
    try:
        symkey = decrypt(private_key, mykey)
    except DecryptionError as e:
        err = DecryptionError(
            f"Failed to decrypt symmetric key for {options.user} in {path}"
        )
        err.__cause__ = e
        error(err, progress, task)
        return None

    # decrypt the file data using the symmetric key
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

    # untar the directory if it was tarred
    if output.suffix == ".tar":
        untar_directory(output, output.parent, options.shred)

    return None
