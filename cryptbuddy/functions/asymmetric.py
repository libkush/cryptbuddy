from nacl.public import PrivateKey, PublicKey, SealedBox

from cryptbuddy.structs.exceptions import DecryptionError, EncryptionError


def encrypt(public_key: PublicKey, message: bytes) -> bytes:
    """
    Encrypts a message asymmetrically with a public key.

    Parameters
    ----------
    public_key : nacl.public.PublicKey
        The public key to encrypt the message with.
    message : bytes
        The message to be encrypted.

    Returns
    -------
    bytes
        The encrypted message.

    See Also
    --------
    decrypt : Decrypts a message asymmetrically with a private key.
    """
    try:
        sealed_box = SealedBox(public_key)
        encrypted = sealed_box.encrypt(message)
    except Exception as e:
        raise EncryptionError("Error encrypting message") from e
    return encrypted


def decrypt(private_key: PrivateKey, encrypted: bytes) -> bytes:
    """
    Decrypts a message asymmetrically with a private key.

    Parameters
    ----------
    private_key : nacl.public.PrivateKey
        The private key to decrypt the message with.
    encrypted : bytes
        The encrypted message.

    Returns
    -------
    bytes
        The decrypted message.

    See Also
    --------
    encrypt : Encrypts a message asymmetrically with a public key.
    """
    try:
        sealed_box = SealedBox(private_key)
        decrypted = sealed_box.decrypt(encrypted)
    except Exception as e:
        raise DecryptionError("Error decrypting message") from e
    return decrypted
