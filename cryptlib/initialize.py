from pathlib import Path
from nacl import encoding
from nacl.public import PrivateKey
from symmetric.encrypt import encrypt


def initialize_cryptbuddy(password: str, dir: str):
    key = PrivateKey.generate()
    file = f"{dir}/private.key"
    with open(file, "wb") as f:
        f.write(key.encode(encoder=encoding.HexEncoder))
    encrypt(file, password)
    Path(file).unlink()
