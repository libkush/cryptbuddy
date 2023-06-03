from shutil import rmtree

from cryptbuddy.config import CACHE_DIR, CONFIG_DIR, DATA_DIR


def clean():
    """Cleans the cache and config directories."""
    for path in [CACHE_DIR, CONFIG_DIR, DATA_DIR]:
        if path.exists():
            rmtree(path)
        path.mkdir(parents=True, exist_ok=True)
