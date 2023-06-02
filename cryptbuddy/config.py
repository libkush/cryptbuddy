from ormsgpack import unpackb

from cryptbuddy.constants import CONFIG_FILE, DEFAULT_CONFIG

config_data = CONFIG_FILE.read_bytes() if CONFIG_FILE.exists() else None
if not config_data:
    CONFIG = DEFAULT_CONFIG
else:
    CONFIG = unpackb(config_data)

CHUNKSIZE = CONFIG["chunksize"]
MACSIZE = CONFIG["macsize"]
OPS = CONFIG["ops"]
MEM = CONFIG["mem"]
KEYSIZE = CONFIG["keysize"]
SALTBYTES = CONFIG["saltbytes"]
NONCESIZE = CONFIG["noncesize"]
DELIMITER = CONFIG["delimiter"]
ESCAPE_SEQUENCE = CONFIG["escape_sequence"]
CACHE_DIR = CONFIG["cache_dir"]
DATA_DIR = CONFIG["data_dir"]
CONFIG_DIR = CONFIG["config_dir"]
SHRED = CONFIG["shred"]
TAR = CONFIG["tar"]
NAME = CONFIG["name"]
