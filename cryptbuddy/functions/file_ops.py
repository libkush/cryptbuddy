from io import BufferedReader, BytesIO
from os import urandom
from pathlib import Path

import msgpack


def shred(path: Path) -> None:
    """
    Overwrites the given file or directory with random data and deletes it.

    Parameters
    ----------
    path : pathlib.Path
        The path to the file or directory to be shredded.
    """
    if not path.exists():
        raise FileNotFoundError("File does not exist")

    paths = [path]
    if path.is_dir():
        # this includes all files subdirectories
        paths = list(path.glob("**/*"))
    for file in paths:
        # we can ignore subdirectories as the files
        # within them are already on the list
        if file.is_dir():
            continue
        size = file.stat().st_size
        random_bits = urandom(size)
        with open(file, "wb") as f:
            f.write(bytes(random_bits))
        file.unlink()


def get_encrypted_outfile(path: Path, output: Path | None = None) -> Path:
    """
    Returns the path to the encrypted file.

    Parameter
    ---------
    path : pathlib.Path
        The path to the file to be encrypted.
    output : pathlib.Path, optional
        The path to the output directory.

    Returns
    -------
    pathlib.Path
        The path to the encrypted file.
    """
    output_dir = output if output else path.parent
    encrypted_name = path.with_suffix(path.suffix + ".crypt").name
    return output_dir / encrypted_name


def get_decrypted_outfile(path: Path, output: Path | None = None) -> Path:
    """
    Returns the path to the decrypted file.

    Parameters
    ----------
    path : pathlib.Path
        The path to the file to be decrypted.
    output : pathlib.Path, optional
        The path to the output directory.

    Returns
    -------
    pathlib.Path
        The path to the decrypted file.
    """
    # if the path ends with .crypt, remove it, otherwise add .dec
    if path.is_dir():
        raise ValueError("Cannot get path for a decrypted directory")
    output_dir = output if output else path.parent
    decrypted_name = (
        path.with_suffix(path.suffix[:-6]).name
        if path.suffix == ".crypt"
        else path.with_suffix(".dec").name
    )
    return output_dir / decrypted_name


def extract_metadata(file: BufferedReader | BytesIO, magicnum: bytes, intsize: int):
    """
    Extracts metadata from a cryptbuddy file.

    Parameters
    ----------
    file : io.BufferedReader | io.BytesIO
        The IO object (file) to get metadata from
    magicnum : bytes
        The magic bytes (signature) of the file
    intisize : int
        The size of the binary integer storing metadata size
    """
    # verify magic bytes at the beginning of the file
    filesig = file.read(len(magicnum))
    if not filesig == magicnum:
        raise ValueError("Unrecognized file type")

    # read how big the metadata is
    metasize = int.from_bytes(file.read(intsize), "big")
    # read those amount of bytes to get the serialized metadata
    meta = file.read(metasize)
    metadata = msgpack.unpackb(meta)
    return metadata
