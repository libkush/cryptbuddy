from pathlib import Path

from cryptbuddy.config import DELIMITER, ESCAPE_SEQUENCE
from cryptbuddy.functions.asymmetric import decrypt, encrypt
from cryptbuddy.functions.file_data import add_meta, parse_data
from cryptbuddy.functions.file_io import shred, tar_directory, write_chunks
from cryptbuddy.functions.symmetric import decrypt_data, encrypt_data
from cryptbuddy.structs.types import AsymmetricDecryptOptions, AsymmetricEncryptOptions


def asymmetric_encrypt(path: Path, options: AsymmetricEncryptOptions, output: Path):
    """
    Encrypts the given file or folder asymmetrically.

    ### Parameters
    - `path` (`Path`): The path to the file or folder to be encrypted.
    - `options` (`AsymmetricEncryptOptions`): The options for encryption.
    - `output` (`Path`): The path to the output file.

    ### Raises
    - `FileNotFoundError`: If the file or folder does not exist.
    """
    if not path.exists():
        raise FileNotFoundError("File or folder does not exist")

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
    """
    Decrypts the given file or folder asymmetrically.

    ### Parameters
    - `path` (`Path`): The path to the file or folder to be decrypted.
    - `options` (`AsymmetricDecryptOptions`): The options for decryption.
    - `output` (`Path`): The path to the output file.

    ### Raises
    - `FileNotFoundError`: If the file or folder does not exist.
    - `ValueError`: If the file is not asymmetrically encrypted.
    """
    if not path.exists():
        raise FileNotFoundError("File or folder does not exist")
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
