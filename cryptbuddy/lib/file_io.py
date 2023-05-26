import random
from pathlib import Path
from typing import List

from appdirs import user_cache_dir, user_config_dir, user_data_dir

from cryptbuddy.lib.utils import info


def shred_file(path: Path) -> None:
    """
    Shreds a file by overwriting its contents with random data and then deleting it.

    Parameters
    ----------
    path : `Path`
        The path to the file to be shredded.

    Returns
    -------
    `None`

    Raises
    ------
    `FileNotFoundError`
        If the file does not exist.

    """
    # Check if the file exists
    if not (path.exists() or path.is_file()):
        raise FileNotFoundError("File does not exist")

    info(f"Shredding {path}")

    # Overwrite the file with random data
    size = path.stat().st_size
    random_bits = random.choices(range(256), k=size)
    with open(path, "wb") as file:
        file.write(bytes(random_bits))

    # Delete the file
    path.unlink()


def write_chunks(chunks: List[bytes], path: Path) -> None:
    """
    Writes the data chunks to a file.

    Parameters
    ----------
    chunks : `List[bytes]`
        The list of data chunks to be written.
    path : `Path`
        The path to the output file.

    Returns
    -------
    `None`

    """
    with open(path, "wb") as outfile:
        for chunk in chunks:
            outfile.write(chunk)


def write_bytes(data: bytes, path: Path) -> None:
    """
    Writes bytes to a file.

    Parameters
    ----------
    data : `bytes`
        The bytes data to be written.
    path : `Path`
        The path to the output file.

    Returns
    -------
    `None`

    """
    with open(path, "wb") as file:
        file.write(data)


### The cache, data and config directories used by cryptbuddy

cache_dir = Path(user_cache_dir("cryptbuddy"))
data_dir = Path(user_data_dir("cryptbuddy"))
config_dir = Path(user_config_dir("cryptbuddy"))


def create_directories() -> None:
    """
    Creates the necessary directories for caching, data, and configuration.

    This function creates the cache directory, data directory, and config directory
    required for the operation of the CryptBuddy application. The directories
    are created using the appropriate paths returned by the appdirs module.

    Returns
    -------
    `None`

    Note
    ----
    The directories are created with the necessary parent directories
    if they do not exist.

    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    data_dir.mkdir(parents=True, exist_ok=True)
    config_dir.mkdir(parents=True, exist_ok=True)
