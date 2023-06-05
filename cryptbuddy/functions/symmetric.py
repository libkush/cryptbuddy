from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

from nacl.bindings import sodium_increment
from nacl.secret import SecretBox
from rich.progress import Progress, TaskID

from cryptbuddy.exceptions import DecryptionError, EncryptionError


def encrypt_chunk(
    index: int, chunk: bytes, box: SecretBox, nonce: bytes, macsize: int
) -> bytes:
    """
    Encrypts the given chunk using the provided key and nonce.

    ### Parameters
    - `chunk` (`bytes`): The chunk to be encrypted.
    - `key` (`bytes`): The encryption key.
    - `nonce` (`bytes`): The nonce to be used for encryption.

    ### Returns
    `bytes`: The encrypted chunk.

    ### Raises
    - `EncryptionError`: If an error occurs during encryption.

    """
    try:
        outchunk = box.encrypt(chunk, nonce).ciphertext
    except Exception as e:
        err = EncryptionError("Error encrypting chunk")
        err.__cause__ = e
        return index, err
    if not len(outchunk) == len(chunk) + macsize:
        return index, EncryptionError("Error encrypting chunk")
    return index, outchunk


def encrypt_data(
    data: bytes,
    key: bytes,
    nonce: bytes,
    chunksize: int,
    macsize: int,
    progress: Progress | None = None,
    task: TaskID | None = None,
) -> List[bytes]:
    """
    Encrypts the given data using the provided key and nonce.

    ### Parameters
    - `data` (`bytes`): The data to be encrypted.
    - `chunksize` (`int`): The size of each chunk to be encrypted.
    - `key` (`bytes`): The encryption key.
    - `nonce` (`bytes`): The nonce to be used for encryption.
    - `macsize` (`int`): The size of the message authentication code.

    ### Returns
    `List[bytes]`: A list of encrypted chunks.

    ### Raises
    - `EncryptionError`: If an error occurs during encryption.

    """
    box = SecretBox(key)
    chunks = [data[i : i + chunksize] for i in range(0, len(data), chunksize)]
    out = [None] * len(chunks)

    with ThreadPoolExecutor() as executor:
        # Process each chunk concurrently and store the future objects
        futures = [
            executor.submit(encrypt_chunk, i, chunk, box, nonce, macsize)
            for i, chunk in enumerate(chunks)
        ]

        for future in as_completed(futures):
            try:
                i, outchunk = future.result()
                if isinstance(outchunk, EncryptionError):
                    raise outchunk
                out[i] = outchunk
                nonce = sodium_increment(nonce)
            except Exception as e:
                raise e
            if progress:
                progress.update(task, advance=chunksize)
    return out


def decrypt_chunk(
    index: int, chunk: bytes, box: SecretBox, nonce: bytes, macsize: int
) -> bytes:
    """
    Decrypts the given chunk using the provided key and nonce.

    ## Parameters
    - `chunk` (`bytes`): The chunk to be decrypted.
    - `key` (`bytes`): The decryption key.
    - `nonce` (`bytes`): The nonce to be used for decryption.

    ## Returns
    `bytes`: The decrypted chunk.

    ## Raises
    - `DecryptionError`: If an error occurs during decryption.

    """
    try:
        outchunk = box.decrypt(chunk, nonce)
    except Exception as e:
        err = DecryptionError("Error decrypting chunk")
        err.__cause__ = e
        return index, err

    if not len(outchunk) == len(chunk) - macsize:
        return index, DecryptionError("Error decrypting chunk")
    return index, outchunk


def decrypt_data(
    data: bytes,
    chunksize: int,
    key: bytes,
    nonce: bytes,
    macsize: int,
    progress: Progress | None = None,
    task: TaskID | None = None,
) -> List[bytes]:
    """
    Decrypts the given data using the provided key and nonce.

    ## Parameters
    - `data` (`bytes`): The data to be decrypted.
    - `chunksize` (`int`): The size of each chunk to be decrypted.
    - `key` (`bytes`): The decryption key.
    - `nonce` (`bytes`): The nonce to be used for decryption.
    - `macsize` (`int`): The size of the message authentication code.

    ## Returns
    `List[bytes]`: A list of decrypted chunks.

    ## Raises
    - `DecryptionError`: If an error occurs during decryption.

    """
    box = SecretBox(key)
    out = [None] * (len(data) // (chunksize + macsize) + 1)
    chunks = [
        data[i : i + chunksize + macsize]
        for i in range(0, len(data), chunksize + macsize)
    ]
    executor = ThreadPoolExecutor()
    # Process each chunk concurrently and store the future objects
    futures = [
        executor.submit(decrypt_chunk, i, chunk, box, nonce, macsize)
        for i, chunk in enumerate(chunks)
    ]

    for future in as_completed(futures):
        try:
            i, outchunk = future.result()
            if isinstance(outchunk, DecryptionError):
                raise outchunk
            out[i] = outchunk
            nonce = sodium_increment(nonce)
        except Exception as e:
            raise e
        if progress:
            progress.update(task, advance=chunksize + macsize)
    return out
