from pathlib import Path

from appdirs import user_cache_dir, user_config_dir, user_data_dir
from nacl import pwhash, secret

NAME = "cryptbuddy"

CACHE_DIR = Path(user_cache_dir(NAME))
DATA_DIR = Path(user_data_dir(NAME))
CONFIG_DIR = Path(user_config_dir(NAME))

if not CACHE_DIR.exists():
    CACHE_DIR.mkdir(parents=True)

if not DATA_DIR.exists():
    DATA_DIR.mkdir(parents=True)

if not CONFIG_DIR.exists():
    CONFIG_DIR.mkdir(parents=True)

CHUNKSIZE = 512 * 1024
PARTSIZE = 300 * 1024 * 1024
MACSIZE = secret.SecretBox.MACBYTES
OPS = pwhash.argon2i.OPSLIMIT_SENSITIVE
MEM = pwhash.argon2i.MEMLIMIT_SENSITIVE
KEYSIZE = secret.SecretBox.KEY_SIZE
NONCESIZE = secret.SecretBox.NONCE_SIZE
SALTBYTES = pwhash.argon2i.SALTBYTES
DELIMITER = b"\xFF\xFF\xFF\xFF"
ESCAPE_SEQUENCE = b"\xAA\xAA\xAA\xAA"
SHRED = True
TAR = True
CPUS = 1

INTSIZE = 16
MAGICNUM = b"\x63\x72\x79\x70\x74\x62\x73\x0C"
DEFAULT_CONFIG = {
    "chunksize": CHUNKSIZE,
    "macsize": MACSIZE,
    "ops": OPS,
    "mem": MEM,
    "keysize": KEYSIZE,
    "saltbytes": SALTBYTES,
    "noncesize": NONCESIZE,
    "delimiter": DELIMITER,
    "escape_sequence": ESCAPE_SEQUENCE,
    "cache_dir": CACHE_DIR,
    "data_dir": DATA_DIR,
    "config_dir": CONFIG_DIR,
    "shred": SHRED,
    "tar": TAR,
    "name": NAME,
    "cpus": CPUS,
}

CONFIG_FILE = CONFIG_DIR / "config.mpk"
