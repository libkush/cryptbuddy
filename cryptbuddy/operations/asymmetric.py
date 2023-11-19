from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import msgpack
from rich.progress import Progress

from cryptbuddy.constants import INTSIZE, MAGICNUM
from cryptbuddy.functions.asymmetric import decrypt, encrypt
from cryptbuddy.functions.file_ops import extract_metadata, shred
from cryptbuddy.functions.symmetric import decrypt_data, encrypt_data
from cryptbuddy.operations.logger import error
from cryptbuddy.structs.exceptions import DecryptionError, EncryptionError
from cryptbuddy.structs.options import (
    AsymmetricDecryptOptions,
    AsymmetricEncryptOptions,
)


def asymmetric_encrypt(
    path: Path,
    options: AsymmetricEncryptOptions,
    output: Path,
    max_partsize: int,
    progress: Progress | None = None,
) -> None:
    """
    Encrypts a file asymmetrically.

    Parameters
    ----------
    path : pathlib.Path
        The path to the file to be encrypted.
    options : cryptbuddy.structs.options.AsymmetricDecryptOptions
        The options for encryption.
    output : pathlib.Path
        The path to the output file.
    max_partsize : int
        Maximum number of bytes to read at once (affects memory usage)
    progress : rich.progress.Progress, optional
        Rich progressbar

    See Also
    --------
    asymmetric_decrypt : Decrypts a file asymmetrically.
    """
    if not path.exists():
        raise FileNotFoundError(f"{path} does not exist")

    task = None
    if progress:
        task = progress.add_task(description=f"Encrypting {path}", total=1)
        progress.start_task(task)

    # encrypt the symmetric key with each recipent's public key
    # and map the encrypted symmetric keys with their respective
    # names
    encrypted_symkeys = {}
    for key in options.public_keys:
        name = key.meta.name
        public_key = key.key
        try:
            encrypted_symkey = encrypt(public_key, options.symkey)
        except EncryptionError as e:
            err = EncryptionError(
                f"Failed to encrypt symmetric key for {name}"
            ).__cause__ = e
            return error(err, getattr(progress, "console", None))
        encrypted_symkeys[name] = encrypted_symkey

    # we need the length of all the parts to be perfectly divisible
    # by the chunksize, so that no trailing data is left
    partsize = max_partsize - max_partsize % options.chunksize

    metadata = {
        "type": options.type,
        "encrypted_symkeys": encrypted_symkeys,
        "nonce": options.nonce,
        "chunksize": options.chunksize,
        "macsize": options.macsize,
        "partsize": partsize,
    }

    infile = open(path, "rb")
    outfile = open(output, "wb")

    meta: bytes = msgpack.packb(metadata)  # type: ignore
    metasize = len(meta).to_bytes(
        INTSIZE,
        "big",
    )
    # the file starts with the magic bytes followed by the
    # size of metadata (to be read) followed by the metadata
    # itself
    outfile.write(MAGICNUM)
    outfile.write(metasize)
    outfile.write(meta)

    executor = ThreadPoolExecutor(max_workers=4)
    nonce = options.nonce

    # we read the file in parts and encrypt each part
    while 1:
        plaintext = infile.read(partsize)
        if len(plaintext) == 0:
            break
        try:
            # the nonce is incremented after each part (see encrypt_data)
            encrypted, nonce = encrypt_data(
                executor,
                plaintext,
                options.symkey,
                nonce,
                options.chunksize,
                options.macsize,
            )
        except Exception as e:
            err = EncryptionError(
                f"Failed to encrypt file data for {path.name}"
            ).__cause__ = e
            return error(err, getattr(progress, "console", None))
        outfile.write(encrypted)

    executor.shutdown()
    infile.close()
    outfile.close()

    # permanently shreds the original file if specified
    if options.shred:
        shred(path)
    if progress and task:
        progress.advance(task)
        progress.update(task, visible=False)


# skipcq: PY-R1000
def asymmetric_decrypt(
    path: Path,
    options: AsymmetricDecryptOptions,
    output: Path,
    max_partsize: int,
    progress: Progress | None = None,
) -> None:
    """
    Decrypts the given file asymmetrically.

    Parameters
    ----------
    path : pathlib.Path
        The path to the file or directory to be decrypted.
    options : cryptbuddy.structs.options.AsymmetricDecryptOptions
        The options for decryption.
    output : pathlib.Path
        The path to the output file.
    max_partsize : int
        Maximum number of bytes to read at once
    progress : rich.progress.Progress, optional
        Rich progressbar.

    See Also
    --------
    asymmetric_encrypt : Encrypts a file asymmetrically.
    """
    if not path.exists():
        raise FileNotFoundError(f"{path} does not exist")

    task = None
    if progress:
        task = progress.add_task(description=f"Decrypting {path}", total=1)
        progress.start_task(task)

    infile = open(path, "rb")
    outfile = open(output, "wb")

    try:
        metadata = extract_metadata(infile, MAGICNUM, INTSIZE)
    except ValueError as e:
        err = ValueError(f"{path} was not encrypted using CryptBuddy").__cause__ = e
        return error(err, getattr(progress, "console", None))

    # verify the metadata is from an asymmetrically encrypted file
    if metadata["type"] != "asymmetric":
        err = ValueError(f"{path} is not asymmetrically encrypted")
        return error(err, getattr(progress, "console", None))

    # get required values from metadata
    encrypted_symkeys: dict[str, bytes] = metadata["encrypted_symkeys"]
    nonce = metadata["nonce"]
    macsize = metadata["macsize"]
    chunksize = metadata["chunksize"]
    partsize = metadata["partsize"]

    # if the user has given partsize that is lower
    # than that used during encryption
    # IT'S NOT POSSIBLE
    if partsize > max_partsize:
        err = ValueError(
            # skipcq: FLK-E501
            f"{path} requires maximum part size to be greater than or equal to {partsize}"
        )
        return error(err, getattr(progress, "console", None))

    if not (encrypted_symkeys and nonce and macsize and chunksize):
        err = ValueError(f"{path} is corrupt")
        return error(err, getattr(progress, "console", None))

    # decrypt the user's private key
    try:
        private_key = options.private_key.decrypted_key(options.password)
    except DecryptionError as e:
        err = DecryptionError(f"Failed to decrypt private key for {options.user}")
        err.__cause__ = e
        return error(err, getattr(progress, "console", None))

    # get the encrypted symmetric key for this user
    mykey = encrypted_symkeys[options.user]
    if not mykey:
        err = ValueError(f"{path} was not encrypted for {options.user}")
        return error(err, getattr(progress, "console", None))

    # decrypt the symmetric key using user's private key
    try:
        symkey = decrypt(private_key, mykey)
    except DecryptionError as e:
        err = DecryptionError(
            f"Failed to decrypt symmetric key for {options.user} in {path}"
        ).__cause__ = e
        return error(err, getattr(progress, "console", None))

    # mental gymnastics to reverse the encryption logic
    chunks_per_part = partsize // chunksize
    part_extrabytes = chunks_per_part * macsize
    executor = ThreadPoolExecutor(max_workers=4)

    while 1:
        ciphertext = infile.read(partsize + part_extrabytes)
        if len(ciphertext) == 0:
            break
        try:
            decrypted, nonce = decrypt_data(
                executor, ciphertext, symkey, nonce, chunksize, macsize
            )
        except Exception as e:
            err = DecryptionError(
                f"Failed to decrypt file data for {path.name}"
            ).__cause__ = e
            return error(err, getattr(progress, "console", None))
        outfile.write(decrypted)

    infile.close()
    outfile.close()
    executor.shutdown()

    if options.shred:
        shred(path)
    if progress and task:
        progress.advance(task)
        progress.update(task, visible=False)
