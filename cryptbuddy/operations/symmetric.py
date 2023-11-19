from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import msgpack
from rich.progress import Progress

from cryptbuddy.constants import INTSIZE, MAGICNUM
from cryptbuddy.functions.file_ops import shred
from cryptbuddy.functions.symmetric import decrypt_data, encrypt_data
from cryptbuddy.operations.logger import error
from cryptbuddy.structs.exceptions import DecryptionError, EncryptionError
from cryptbuddy.structs.options import SymmetricDecryptOptions, SymmetricEncryptOptions


def symmetric_encrypt(
    path: Path,
    options: SymmetricEncryptOptions,
    output: Path,
    max_partsize: int,
    progress: Progress | None = None,
) -> None:
    """
    Encrypts a file symmetrically.

    Parameters
    ----------
    path : pathlib.Path
        The path to the file to be encrypted.
    options : cryptbuddy.structs.options.SymmetricEncryptOptions
        The options for encryption.
    output : pathlib.Path
        The path to the output file.
    max_partsize : int
        Maximum number of bytes to read at once. (affects memory usage)
    progress : rich.progress.Progress, optional
        Rich progressbar.

    See Also
    --------
    symmetric_decrypt : Decrypts a file symmetrically.
    """
    # the logic in this function is pretty identical (and simpler) to the one
    # described in asymmetric_encrypt() function. GO READ IT!
    if not path.exists():
        raise FileNotFoundError(f"{path} does not exist")

    partsize = max_partsize - max_partsize % options.chunksize

    task = None
    if progress:
        task = progress.add_task(description=f"Encrypting {path}", total=1)

    metadata = {
        "type": options.type,
        "nonce": options.nonce,
        "salt": options.salt,
        "ops": options.ops,
        "mem": options.mem,
        "chunksize": options.chunksize,
        "macsize": options.macsize,
        "keysize": options.keysize,
        "partsize": partsize,
    }

    infile = open(path, "rb")
    outfile = open(output, "wb")

    meta: bytes = msgpack.packb(metadata)  # type: ignore
    metasize = len(meta).to_bytes(
        INTSIZE,
        "big",
    )
    outfile.write(MAGICNUM)
    outfile.write(metasize)
    outfile.write(meta)

    executor = ThreadPoolExecutor(max_workers=4)
    nonce = options.nonce
    while 1:
        plaintext = infile.read(partsize)
        if len(plaintext) == 0:
            break
        try:
            encrypted, nonce = encrypt_data(
                executor,
                plaintext,
                options.key,
                nonce,
                options.chunksize,
                options.macsize,
            )
        except Exception as e:
            err = EncryptionError(
                f"Failed to encrypt file data for {path.name}"
            ).__cause__ = e
            if progress:
                return error(err, progress.console)
            return print(e)
        outfile.write(encrypted)

    executor.shutdown()
    infile.close()
    outfile.close()

    if options.shred:
        shred(path)
    if progress and task:
        progress.advance(task)
        progress.update(task, visible=False)


def symmetric_decrypt(
    path: Path,
    options: SymmetricDecryptOptions,
    output: Path,
    max_partsize: int,
    progress: Progress | None = None,
) -> None:
    """
    Decrypts a file symmetrically.

    Parameters
    ----------
    path : pathlib.Path
        The path to the file to be decrypted.
    options : cryptbuddy.structs.options.SymmetricDecryptOptions
        The options for decryption.
    output : pathlib.Path
        The path to the output file.
    max_partsize : int
        Maximum number of bytes to read at once.
    progress : rich.progress.Progress, optional
        Rich progressbar.

    See Also
    --------
    symmetric_encrypt : Encrypts a file symmetrically.
    """
    # Again, read asymmetric_decrypt() function to understand the logic
    if not path.exists():
        raise FileNotFoundError(f"{path} does not exist")

    task = None
    if progress:
        task = progress.add_task(description=f"Decrypting {path}", total=1)

    infile = open(path, "rb")
    outfile = open(output, "wb")

    filesig = infile.read(len(MAGICNUM))
    if not filesig == MAGICNUM:
        err = ValueError(f"{path} was not encrypted using CryptBuddy")
        if progress:
            return error(err, progress.console)
        return print(err)

    metasize = int.from_bytes(infile.read(INTSIZE), "big")
    meta = infile.read(metasize)
    metadata = msgpack.unpackb(meta)
    if metadata["type"] != "symmetric":
        err = ValueError(f"{path} is not symmetrically encrypted")
        if progress:
            return error(err, progress.console)
        return print(err)
    ops = metadata["ops"]
    mem = metadata["mem"]
    salt = metadata["salt"]
    nonce = metadata["nonce"]
    chunksize = metadata["chunksize"]
    macsize = metadata["macsize"]
    keysize = metadata["keysize"]
    partsize = metadata["partsize"]
    chunks_per_part = partsize // chunksize

    if partsize > max_partsize:
        # skipcq: FLK-E501
        e = ValueError(
            f"{path} requires maximum part size to be greater than or equal to {partsize}"
        )
        if progress:
            return error(e, progress.console)
        return print(e)

    if not (ops and mem and salt and nonce and chunksize and macsize and keysize):
        err = ValueError(f"{path} is corrupt")
        if progress:
            return error(err, progress.console)
        return print(err)

    key = options.get_key(salt, mem, ops, keysize)
    part_extrabytes = chunks_per_part * macsize
    executor = ThreadPoolExecutor(max_workers=4)

    while 1:
        ciphertext = infile.read(partsize + part_extrabytes)
        if len(ciphertext) == 0:
            break
        try:
            decrypted, nonce = decrypt_data(
                executor, ciphertext, key, nonce, chunksize, macsize
            )
        except Exception as e:
            err = DecryptionError(
                f"Failed to decrypt file data for {path.name}"
            ).__cause__ = e
            if progress:
                return error(err, progress.console)
            return print(err)
        outfile.write(decrypted)

    infile.close()
    outfile.close()
    executor.shutdown()

    if options.shred:
        shred(path)
    if progress and task:
        progress.advance(task)
        progress.update(task, visible=False)
