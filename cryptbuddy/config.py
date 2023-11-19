from pathlib import Path

import msgpack

from cryptbuddy.constants import (
    CONFIG_FILE,
    DEFAULT_CONFIG,
    KEYSIZE,
    MACSIZE,
    NONCESIZE,
    SALTBYTES,
)

config_data = CONFIG_FILE.read_bytes() if CONFIG_FILE.exists() else None
if not config_data:
    CONFIG = DEFAULT_CONFIG
else:
    CONFIG = msgpack.unpackb(config_data)

KEYSIZE: int = KEYSIZE
SALTBYTES: int = SALTBYTES
NONCESIZE: int = NONCESIZE
MACSIZE: int = MACSIZE

CHUNKSIZE: int = CONFIG["chunksize"]
OPS = CONFIG["ops"]
MEM = CONFIG["mem"]
DELIMITER: bytes = CONFIG["delimiter"]
ESCAPE_SEQUENCE: bytes = CONFIG["escape_sequence"]
CACHE_DIR: Path = CONFIG["cache_dir"]
DATA_DIR: Path = CONFIG["data_dir"]
CONFIG_DIR: Path = CONFIG["config_dir"]
SHRED: bool = CONFIG["shred"]
TAR: bool = CONFIG["tar"]
NAME: str = CONFIG["name"]
CPUS: int = CONFIG["cpus"]
