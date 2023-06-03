from typing import List

from nacl.bindings import sodium_increment
from nacl.secret import SecretBox
from rich.progress import Progress, TaskID

from cryptbuddy.exceptions import DecryptionError, EncryptionError


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
    out = []

    while 1:
        chunk = data[:chunksize]
        if len(chunk) == 0:
            break
        try:
            outchunk = box.encrypt(chunk, nonce).ciphertext
        except Exception as e:
            raise EncryptionError("Error encrypting chunk") from e
        assert len(outchunk) == len(chunk) + macsize
        out.append(outchunk)
        nonce = sodium_increment(nonce)
        data = data[chunksize:]
        progress.update(task, advance=chunksize) if progress else None

    return out


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
    out = []
    while 1:
        rchunk = data[: chunksize + macsize]
        if len(rchunk) == 0:
            break
        try:
            dchunk = box.decrypt(rchunk, nonce)
        except Exception as e:
            raise DecryptionError("Error decrypting chunk") from e
        assert len(dchunk) == len(rchunk) - macsize
        out.append(dchunk)
        nonce = sodium_increment(nonce)
        data = data[chunksize + macsize :]
        progress.update(task, advance=chunksize) if progress else None
    return out
