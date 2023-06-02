from pathlib import Path

from cryptbuddy.config import DELIMITER, ESCAPE_SEQUENCE
from cryptbuddy.functions.file_data import add_meta, parse_data
from cryptbuddy.functions.file_io import shred, tar_directory, write_chunks
from cryptbuddy.functions.symmetric import decrypt_data, encrypt_data
from cryptbuddy.structs.types import SymmetricDecryptOptions, SymmetricEncryptOptions


def symmetric_encrypt(path: Path, options: SymmetricEncryptOptions, output: Path):
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

    # encrypt the file data
    encrypted_data = encrypt_data(
        file_data,
        options.key,
        options.nonce,
        options.chunksize,
        options.macsize,
    )

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


def symmetric_decrypt(path: Path, options: SymmetricDecryptOptions, output: Path):
    # read the file data
    encrypted_data = path.read_bytes()

    # get the metadata
    meta, encrypted_data = parse_data(encrypted_data, DELIMITER, ESCAPE_SEQUENCE)

    if meta["type"] != "symmetric":
        raise Exception("Invalid file type")

    ops = meta["ops"]
    mem = meta["mem"]
    salt = meta["salt"]
    nonce = meta["nonce"]
    chunksize = meta["chunksize"]
    macsize = meta["macsize"]
    keysize = meta["keysize"]

    key = options.get_key(salt, mem, ops, keysize)

    # decrypt the file data
    decrypted_data = decrypt_data(
        encrypted_data,
        chunksize,
        key,
        nonce,
        macsize,
    )

    if options.shred:
        shred(path)

    write_chunks(decrypted_data, output)