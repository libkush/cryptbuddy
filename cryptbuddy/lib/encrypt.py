from pathlib import Path
from typing import List

from cryptbuddy.lib.constants import *
from cryptbuddy.lib.key_io import AppPublicKey
from cryptbuddy.lib.keychain import Keychain
from cryptbuddy.lib.symmetric.encrypt import symmetric_encrypt
from cryptbuddy.lib.utils import *
from msgpack import dumps
from nacl import utils
from nacl.public import PublicKey, SealedBox


def asymmetric_encrypt(users: List[str], file: Path) -> List[bytes]:
    """
    Encrypts a file asymmetrically for multiple users. This function generates 
    a random symmetric key, encrypts it with the public keys of the specified 
    users, and stores the encrypted symmetric keys in the file. The file is then 
    symmetrically encrypted using the symmetric key, and the encrypted symmetric 
    keys are stored in the file as well.

    Parameters
    ----------
    users : `List[str]`
        The list of users for whom the file is encrypted.
    file : `Path`
        The path to the file to be encrypted.

    Returns
    -------
    `List[bytes]`
        A list of encrypted data chunks.

    Raises
    ------
    `Exception`
        If no public keys are found.

    Notes
    -----
    The file must be decrypted using the corresponding `asymmetric_decrypt` function.

    """

    info(f"Encrypting {file} for {users}")

    db = Keychain()

    public_keys_packed = []
    for u in users:
        public_keys_packed.append(db.get_key(name=u).packed)
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
    # using a delimiter
    packed_keys = dumps(encrypted_symmetric_keys)
    packed_keys = packed_keys.replace(delimiter, escape_sequence + delimiter)
    chunks.insert(0, delimiter)
    chunks.insert(0, packed_keys)

    return chunks
