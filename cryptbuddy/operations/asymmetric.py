from pathlib import Path

from nacl.public import PublicKey

from cryptbuddy.config import DELIMITER, ESCAPE_SEQUENCE
from cryptbuddy.functions.asymmetric import decrypt, encrypt
from cryptbuddy.functions.file_data import add_meta, parse_data
from cryptbuddy.functions.file_io import shred, tar_directory, write_chunks
from cryptbuddy.functions.symmetric import decrypt_data, encrypt_data
from cryptbuddy.structs.types import AsymmetricDecryptOptions, AsymmetricEncryptOptions


def asymmetric_encrypt(path: Path, options: AsymmetricEncryptOptions, output: Path):
    encrypted_symkeys = {}
    to_shred = options.shred
    for key in options.public_keys:
        name = key.meta.name
        public_key = key.key
        encrypted_symkey = encrypt(public_key, options.symkey)
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

    # encrypt the file data
    encrypted_data = encrypt_data(
        file_data, options.symkey, options.nonce, options.chunksize, options.macsize
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


def asymmetric_decrypt(path: Path, options: AsymmetricDecryptOptions, output: Path):
    # read the file data
    encrypted_data = path.read_bytes()

    # get the metadata
    meta, encrypted_data = parse_data(encrypted_data, DELIMITER, ESCAPE_SEQUENCE)

    if not meta["type"] == "asymmetric":
        raise ValueError("File is not asymmetrically encrypted")

    encrypted_symkeys: dict[str, bytes] = meta["encrypted_symkeys"]
    nonce = meta["nonce"]
    macsize = meta["macsize"]
    chunksize = meta["chunksize"]

    mykey = encrypted_symkeys[options.user]
    private_key = options.private_key.decrypted_key(options.password)

    # decrypt symkey
    symkey = decrypt(private_key, mykey)

    # decrypt the file data
    file_data = decrypt_data(encrypted_data, chunksize, symkey, nonce, macsize)

    if options.shred:
        shred(path)

    write_chunks(file_data, output)
