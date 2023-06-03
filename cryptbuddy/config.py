from pathlib import Path

from ormsgpack import unpackb

from cryptbuddy.constants import CONFIG_FILE, DEFAULT_CONFIG

config_data = CONFIG_FILE.read_bytes() if CONFIG_FILE.exists() else None
if not config_data:
    CONFIG = DEFAULT_CONFIG
else:
    CONFIG = unpackb(config_data)

CHUNKSIZE: int = CONFIG["chunksize"]
MACSIZE: int = CONFIG["macsize"]
OPS = CONFIG["ops"]
MEM = CONFIG["mem"]
KEYSIZE: int = CONFIG["keysize"]
SALTBYTES: int = CONFIG["saltbytes"]
NONCESIZE: int = CONFIG["noncesize"]
DELIMITER: bytes = CONFIG["delimiter"]
ESCAPE_SEQUENCE: bytes = CONFIG["escape_sequence"]
CACHE_DIR: Path = CONFIG["cache_dir"]
DATA_DIR: Path = CONFIG["data_dir"]
CONFIG_DIR: Path = CONFIG["config_dir"]
SHRED: bool = CONFIG["shred"]
TAR: bool = CONFIG["tar"]
NAME: str = CONFIG["name"]
