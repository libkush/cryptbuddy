import tarfile
from os import urandom
from pathlib import Path
from typing import List


def write_chunks(chunks: List[bytes], path: Path) -> None:
    """
    Writes the given binary chunks to a file.

    ### Parameters
    - `chunks` (`List[bytes]`): The chunks to be written.
    - `path` (`Path`): The path to the file to be written.

    ### Raises
    - `ValueError`: If the path is a directory.
    """
    if path.exists() and path.is_dir():
        raise ValueError("Cannot write chunks to a directory")
    if not path.parent.exists():
        path.parent.mkdir(parents=True)
    if not path.exists():
        path.touch()
    with open(path, "wb") as outfile:
        outfile.write(
            b"".join(chunks) if chunks[-1] is not None else b"".join(chunks[:-1])
        )


def write_bytes(b: bytes, path: Path) -> None:
    """
    Writes the given bytes to a file.

    ### Parameters
    - `b` (`bytes`): The bytes to be written.
    - `path` (`Path`): The path to the file to be written.

    ### Raises
    - `ValueError`: If the path is a directory.
    """
    if path.exists() and path.is_dir():
        raise ValueError("Cannot write bytes to a directory")
    if not path.parent.exists():
        path.parent.mkdir(parents=True)
    if not path.exists():
        path.touch()
    with open(path, "wb") as outfile:
        outfile.write(b)


def shred(path: Path) -> None:
    """
    Overwrites the given file or folder with random data and deletes it.

    ### Parameters
    - `path` (`Path`): The path to the file to be shredded.

    ### Raises
    - `FileNotFoundError`: If the file or folder does not exist.
    """
    if not path.exists():
        raise FileNotFoundError("File does not exist")

    paths = [path]
    if path.is_dir():
        paths = list(path.glob("**/*"))

    for file in paths:
        # overwrite the file with random data
        size = file.stat().st_size
        random_bits = urandom(size)
        with open(file, "wb") as f:
            f.write(bytes(random_bits))

        # delete the file
        file.unlink()


def tar_directory(path: Path) -> Path:
    """
    Creates a tar archive of the given directory.

    ### Parameters
    - `path` (`Path`): The path to the directory to be archived.

    ### Raises
    - `ValueError`: If the path is not a directory.
    """
    if not path.is_dir():
        raise ValueError("Path is not a directory")

    # create a tar archive of the directory
    with tarfile.open(path.with_suffix(".tar"), "w") as tar:
        tar.add(path, arcname=path.name)

    return path.with_suffix(".tar").absolute()


def untar_directory(path: Path, output: Path, shred_file: bool) -> Path:
    """
    Extracts a tar archive to the given directory.

    ### Parameters
    - `path` (`Path`): The path to the tar archive.
    - `output` (`Path`): The path to the directory to extract to.
    - `shred` (`bool`): Whether to shred the tar archive after extraction.

    ### Raises
    - `ValueError`: If the path is not a tar archive.
    """
    if not path.is_file() or path.suffix != ".tar":
        raise ValueError("Path is not a tar archive")

    # extract the tar archive to the output directory
    with tarfile.open(path, "r") as tar:
        tar.extractall(output)

    if shred_file:
        shred(path)

    return output


def get_encrypted_outfile(path: Path, output: Path = None):
    """
    Returns the path to the encrypted file.

    ### Parameters
    - `path` (`Path`): The path to the file to be encrypted.
    - `output` (`Path`): The path to the output directory.

    ### Returns
    - `Path`: The path to the encrypted file.
    """
    # if the file is a directory, add .tar.crypt to the end
    # otherwise, add .crypt to the end
    output_dir = output if output else path.parent
    encrypted_name = path.with_suffix(path.suffix + ".crypt").name
    if path.is_dir():
        encrypted_name = path.with_suffix(".tar.crypt").name
    return output_dir / encrypted_name


def get_decrypted_outfile(path: Path, output: Path = None):
    """
    Returns the path to the decrypted file.

    ### Parameters
    - `path` (`Path`): The path to the file to be decrypted.
    - `output` (`Path`): The path to the output directory.

    ### Returns
    - `Path`: The path to the decrypted file.

    ### Raises
    - `ValueError`: If the path is a directory.
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
