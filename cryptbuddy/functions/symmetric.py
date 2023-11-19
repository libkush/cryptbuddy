from concurrent.futures import ThreadPoolExecutor
from typing import Tuple

from nacl.bindings import sodium_increment
from nacl.secret import SecretBox

from cryptbuddy.structs.exceptions import DecryptionError, EncryptionError


def encrypt_chunk(args: Tuple[bytes, SecretBox, bytes]) -> bytes:
    """
    Encrypts a chunk using the provided key and nonce.

    Parameters
    ----------
    args : Tuple[bytes, SecretBox, bytes]
        A tuple containing the chunk with SecretBox and nonce

    Returns
    -------
    bytes
        The encrypted chunk.
    """
    chunk, box, nonce = args
    return box.encrypt(chunk, nonce).ciphertext


def encrypt_data(
    executor: ThreadPoolExecutor,
    data: bytes,
    key: bytes,
    nonce: bytes,
    chunksize: int,
    macsize: int,
) -> Tuple[bytes, bytes]:
    """
    Encrypts data using the provided key and nonce.

    Parameters
    ----------
    data : bytes
        The data to be encrypted.
    key : bytes
        The encryption key.
    nonce : bytes
        The nonce to be used for encryption.
    chunksize : int
        The size of each chunk to be encrypted.
    macsize : int
        The size of the message authentication code.

    Returns
    -------
    bytes
        Encrypted data.
    bytes
        Incremented nonce value after the last chunk
    """
    # we will create a list of arguments to provide to the
    # encrypt_chunk() function by dividing the data into chunks
    # and incrementing the nonce value for each chunk to avoid
    # repetition of nonce
    box = SecretBox(key)
    args = []
    total = len(data)
    i = 0
    while i < total:
        chunk = data[i : i + chunksize]
        nonce = sodium_increment(nonce)
        args.append((chunk, box, nonce))
        i += chunksize

    # the thread pool will encrypt each chunk in parallel
    out = b"".join(executor.map(encrypt_chunk, args))

    # the output of each chunk has mac bytes for authentication
    # hence the expected size is number of args times
    # chunksize + macsize
    # however if data is present in a single chunk, the
    # size is length of data + macsize
    expected_outsize = (
        (chunksize + macsize) * len(args) if (len(args) > 1) else total + macsize
    )
    if not len(out) == expected_outsize:
        raise EncryptionError("Error encrypting given data")

    # since this function is meant to be called from
    # symmetric_encrypt() function, we need to return the
    # incremented nonce value after the last chunk
    nextnonce = sodium_increment(nonce)
    return out, nextnonce


def decrypt_chunk(args: Tuple[bytes, SecretBox, bytes]) -> bytes:
    """
    Decrypts the given chunk using the provided key and nonce.

    Parameters
    ----------
    args : Tuple[bytes, SecretBox, bytes]
        A tuple containing the chunk with SecretBox and nonce

    Returns
    -------
    bytes
        The decrypted chunk.
    """
    chunk, box, nonce = args
    return box.decrypt(chunk, nonce)


def decrypt_data(
    executor: ThreadPoolExecutor,
    data: bytes,
    key: bytes,
    nonce: bytes,
    chunksize: int,
    macsize: int,
) -> Tuple[bytes, bytes]:
    """
    Decrypts the given data using the provided key and nonce.

    Parameters
    ----------
    data : bytes
        The data to be decrypted.
    key : bytes
        The decryption key.
    nonce : bytes
        The nonce to be used for decryption.
    chunksize : int
        The size of each chunk to be decrypted.
    macsize : int
        The size of the message authentication code.

    Returns
    -------
    bytes
        Decrypted data.
    bytes
        Incremented nonce value after the last chunk
    """
    # same logic to create a list of arguments as above
    box = SecretBox(key)
    args = []
    total = len(data)
    i = 0
    while i < total:
        chunk = data[i : i + chunksize + macsize]
        nonce = sodium_increment(nonce)
        args.append((chunk, box, nonce))
        i += chunksize + macsize
    out = b"".join(executor.map(decrypt_chunk, args))

    # the outsize here is just the chunksize times total chunks
    # but if there's just one chunk, it will be the size of
    # encrypted data minus the macsize
    expected_outsize = chunksize * len(args) if (len(args) > 1) else total - macsize
    if not len(out) == expected_outsize:
        raise DecryptionError("Error decrypting given data")

    nextnonce = sodium_increment(nonce)
    return out, nextnonce
