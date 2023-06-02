from nacl.public import PrivateKey, PublicKey, SealedBox


def encrypt(public_key: PublicKey, message: bytes) -> bytes:
    sealed_box = SealedBox(public_key)
    encrypted = sealed_box.encrypt(message)
    return encrypted


def decrypt(private_key: PrivateKey, encrypted: bytes) -> bytes:
    sealed_box = SealedBox(private_key)
    decrypted = sealed_box.decrypt(encrypted)
    return decrypted
