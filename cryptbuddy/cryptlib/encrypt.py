from pathlib import Path

from cryptbuddy.cryptlib.constants import *
from cryptbuddy.cryptlib.key_io import AppPublicKey
from cryptbuddy.cryptlib.keychain import keychain
from cryptbuddy.cryptlib.symmetric.encrypt import symmetric_encrypt
from msgpack import dumps
from nacl import utils
from nacl.public import PublicKey, SealedBox


def asymmetric_encrypt(user: list, file: Path):
    """
    Returns asymmetrically encrypted chunks. `user` is a list of 
    usernames whose public keys will be used to encrypt the file. 
    `file` is the file to be encrypted.
    """

    # Initialize the keychain
    db = keychain()

    # Get the public keys of the users from the keychain
    public_keys_packed = []
    for u in user:
        public_keys_packed.append(db.get_key(name=u))
    if len(public_keys_packed) == 0:
        raise Exception("No public keys found")

    # Deserialize the public keys
    public_keys = {}
    for key in public_keys_packed:
        unpacked_key = AppPublicKey.from_packed(key)
        public_keys[unpacked_key.meta.name] = unpacked_key

    # Generate a random symmetric key
    symmetric_key = utils.random(keysize)

    # Encrypt the symmetric key with all the public keys
    # and store them in a dictionary with the name of the
    # user with the key
    encrypted_symmetric_keys = {}
    for name, public_key in public_keys.items():
        public_key_object = PublicKey(public_key.key)
        sealed_box = SealedBox(public_key_object)
        encrypted = sealed_box.encrypt(symmetric_key)
        encrypted_symmetric_keys[name] = encrypted

    # Encrypt the file symmetrically with the symmetric key
    chunks = symmetric_encrypt(file, key=symmetric_key)

    # Serialize the encrypted symmetric keys and prepend it
    # using a newline
    packed_keys = dumps(encrypted_symmetric_keys)
    chunks.insert(0, b'\n')
    chunks.insert(0, packed_keys)

    # Return the encrypted chunks
    return chunks
