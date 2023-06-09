from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

from nacl.bindings import sodium_increment
from nacl.secret import SecretBox
from rich.progress import TaskID

from cryptbuddy.structs.exceptions import DecryptionError, EncryptionError
from cryptbuddy.structs.types import ProgressState


def encrypt_chunk(
    index: int, chunk: bytes, box: SecretBox, nonce: bytes, macsize: int
) -> bytes:
    """
    Encrypts the given chunk using the provided key and nonce.

    ### Parameters
    - `index` (`int`): The index of the chunk.
    - `chunk` (`bytes`): The chunk to be encrypted.
    - `box` (`SecretBox`): The encryption box.
    - `nonce` (`bytes`): The nonce to be used for encryption.
    - `macsize` (`int`): The size of the authentication MAC tag in bytes.

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
    progress: ProgressState | None = None,
    task: TaskID | None = None,
) -> List[bytes]:
    """
    Encrypts the given data using the provided key and nonce.

    ### Parameters
    - `data` (`bytes`): The data to be encrypted.
    - `key` (`bytes`): The encryption key.
    - `nonce` (`bytes`): The nonce to be used for encryption.
    - `chunksize` (`int`): The size of each chunk to be encrypted.
    - `macsize` (`int`): The size of the message authentication code.
    - `progress` (`ProgressState`): The shared progress state object.
    - `task` (`TaskID`): The task ID of the current task.

    ### Returns
    `List[bytes]`: A list of encrypted chunks.

    ### Raises
    - `EncryptionError`: If an error occurs during encryption.

    """
    box = SecretBox(key)
    chunks = [data[i : i + chunksize] for i in range(0, len(data), chunksize)]
    # create a list of the same length as the number of chunks
    out = [None] * len(chunks)
    total = len(chunks)
    # set the progress to the total number of chunks
    if progress:
        progress.update(task, total=total)

    with ThreadPoolExecutor() as executor:
        # process each chunk concurrently and store the future objects
        futures = [
            executor.submit(encrypt_chunk, i, chunk, box, nonce, macsize)
            # enumerate the chunks to get the index
            for i, chunk in enumerate(chunks)
        ]

        for future in as_completed(futures):
            try:
                # get the index and encrypted chunk
                i, outchunk = future.result()

                # if the result is an error, raise it
                if isinstance(outchunk, EncryptionError):
                    raise outchunk

                # otherwise, store the encrypted chunk
                out[i] = outchunk
                nonce = sodium_increment(nonce)

            except Exception as e:
                raise e

            if progress:
                progress.increment(task)
    return out


def decrypt_chunk(
    index: int, chunk: bytes, box: SecretBox, nonce: bytes, macsize: int
) -> bytes:
    """
    Decrypts the given chunk using the provided key and nonce.

    ## Parameters
    - `index` (`int`): The index of the chunk.
    - `chunk` (`bytes`): The chunk to be decrypted.
    - `box` (`SecretBox`): The decryption box.
    - `nonce` (`bytes`): The nonce to be used for decryption.
    - `macsize` (`int`): The size of the authentication MAC tag in bytes.

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
    progress: ProgressState | None = None,
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
    - `progress` (`ProgressState`): The shared progress state object.
    - `task` (`TaskID`): The task ID of the current task.

    ## Returns
    `List[bytes]`: A list of decrypted chunks.

    ## Raises
    - `DecryptionError`: If an error occurs during decryption.

    """
    box = SecretBox(key)

    # the chunksize is the size of the chunk plus the size of the mac
    chunks = [
        data[i : i + chunksize + macsize]
        for i in range(0, len(data), chunksize + macsize)
    ]
    # create a list of the same length as the number of chunks
    out = [None] * len(chunks)

    total = len(chunks)
    if progress:
        progress.update(task, total=total)

    # process each chunk concurrently and store the future objects
    executor = ThreadPoolExecutor()
    futures = [
        executor.submit(decrypt_chunk, i, chunk, box, nonce, macsize)
        # enumerate the chunks to get the index
        for i, chunk in enumerate(chunks)
    ]

    for future in as_completed(futures):
        try:
            # get the index and decrypted chunk
            i, outchunk = future.result()
            if isinstance(outchunk, DecryptionError):
                raise outchunk
            out[i] = outchunk
            nonce = sodium_increment(nonce)
        except Exception as e:
            raise e
        if progress:
            progress.increment(task)
    return out
