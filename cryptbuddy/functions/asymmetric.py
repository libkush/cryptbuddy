from nacl.public import PrivateKey, PublicKey, SealedBox

from cryptbuddy.exceptions import DecryptionError, EncryptionError


def encrypt(public_key: PublicKey, message: bytes) -> bytes:
    """
    Encrypts a message with a public key.

    ### Parameters
    - `public_key` (`PublicKey`): The public key to encrypt the message with.
    - `message` (`bytes`): The message to be encrypted.

    ### Returns
    `bytes`: The encrypted message.

    ### Raises
    - `EncryptionError`: If an error occurs during encryption.
    """
    try:
        sealed_box = SealedBox(public_key)
        encrypted = sealed_box.encrypt(message)
    except Exception as e:
        raise EncryptionError("Error encrypting message") from e
    return encrypted


def decrypt(private_key: PrivateKey, encrypted: bytes) -> bytes:
    """
    Decrypts a message with a private key.

    ### Parameters
    - `private_key` (`PrivateKey`): The private key to decrypt the message with.
    - `encrypted` (`bytes`): The encrypted message.

    ### Returns
    `bytes`: The decrypted message.

    ### Raises
    - `DecryptionError`: If an error occurs during decryption.
    """

    try:
        sealed_box = SealedBox(private_key)
        decrypted = sealed_box.decrypt(encrypted)
    except Exception as e:
        raise DecryptionError("Error decrypting message") from e
    return decrypted
