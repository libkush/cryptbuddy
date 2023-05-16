from pathlib import Path
from cryptlib.keychain import keychain
from cryptlib.key_io import AppPublicKey, AppPrivateKey
from nacl import utils
from cryptlib.constants import *
from nacl.public import PublicKey, SealedBox
from cryptlib.symmetric.encrypt import symmetric_encrypt
from cryptlib.symmetric.decrypt import symmetric_decrypt
from msgpack import dumps, loads


def asymmetric_encrypt(user: list, file: Path):
    db = keychain()
    public_keys_packed = []
    for u in user:
        public_keys_packed.append(db.get_key(name=u))
    if len(public_keys_packed) == 0:
        raise Exception("No public keys found")
    public_keys = {}
    for key in public_keys_packed:
        unpacked_key = AppPublicKey.from_packed(key)
        public_keys[unpacked_key.meta.name] = unpacked_key
    symmetric_key = utils.random(keysize)
    encrypted_symmetric_keys = {}
    for name, public_key in public_keys.items():
        public_key_object = PublicKey(public_key.key)
        sealed_box = SealedBox(public_key_object)
        encrypted = sealed_box.encrypt(symmetric_key)
        encrypted_symmetric_keys[name] = encrypted
    chunks = symmetric_encrypt(file, key=symmetric_key)
    del symmetric_key, public_keys, public_keys_packed, public_key_object, sealed_box, encrypted
    packed_keys = dumps(encrypted_symmetric_keys)
    chunks.insert(0, b'\n')
    chunks.insert(0, packed_keys)
    return chunks
