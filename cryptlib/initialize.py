from nacl import encoding
from nacl.public import PrivateKey


def initialize_cryptbuddy():
    key = PrivateKey.generate()
    with open(f"{dir}/private.key", "wb") as f:
        f.write(key.encode(encoder=encoding.HexEncoder))
