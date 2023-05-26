import sqlite3
from typing import Tuple

from cryptbuddy.lib.file_io import *
from cryptbuddy.lib.key_io import AppPublicKey

create_directories()


class Keychain:
    """
    Keychain in CryptBuddy.

    Methods
    -------
    __init__()
        Initialize the Keychain.
    add_key(key: `AppPublicKey`)
        Add a key to the keychain.
    get_key(name: `str = None`, id: `int = None`) -> AppPublicKey
        Retrieve a key from the keychain.
    get_names() -> `List[Tuple[int, str]]`
        Retrieve the names of keys in the keychain.
    delete_key(name: `str = None`, id: `int = None`)
        Delete a key from the keychain.
    close()
        Close the keychain connection.

    """

    def __init__(self):
        conn = sqlite3.connect(f"{data_dir}/keychain.db")
        c = conn.cursor()

        # Create the keys table if it doesn't exist
        create_query = """
            CREATE TABLE IF NOT EXISTS keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                key BLOB NOT NULL
            )
        """
        c.execute(create_query)
        conn.commit()

        # Set the connection and cursor attributes
        self.conn = conn
        self.c = c

    def add_key(self, key: AppPublicKey) -> None:
        """
        Add a key to the keychain.

        Parameters
        ----------
        key : `AppPublicKey`
            Public key object.

        """
        info(f"Adding key {key.meta.name} to keychain")
        self.c.execute(
            "INSERT INTO keys (name, key) VALUES (?, ?)", (key.meta.name, key.packed)
        )
        self.conn.commit()

    def get_key(self, name: str = None, id: int = None) -> AppPublicKey:
        """
        Retrieve a key from the keychain.

        Parameters
        ----------
        name : `str`, optional
            Name of the key.
        id : `int`, optional
            ID of the key.

        Returns
        -------
        `AppPublicKey`
            Public key object.

        Raises
        ------
        `ValueError`
            If neither name nor ID is specified.
        `TypeError`
            If the key is not found.

        """
        if not name and not id:
            raise ValueError("Must specify name or ID")

        if id:
            info(f"Retrieving key {id} from keychain")
            self.c.execute("SELECT key FROM keys WHERE id = ?", (id,))
        else:
            info(f"Retrieving key {name} from keychain")
            self.c.execute("SELECT key FROM keys WHERE name = ?", (name,))

        result = self.c.fetchone()
        if result is None:
            raise TypeError("Key not found")

        return AppPublicKey.from_packed(result[0])

    def get_names(self) -> List[Tuple[int, str]]:
        """
        Retrieve all the names of keys in the keychain.

        Returns
        -------
        `List[Tuple[int, str]]`
            List of tuples containing key IDs and names.

        """
        self.c.execute("SELECT id, name FROM keys")
        return self.c.fetchall()

    def delete_key(self, name: str = None, id: int = None) -> None:
        """
        Delete a key from the keychain.

        Parameters
        ----------
        name : `str`, optional
            Name of the key.
        id : `int`, optional
            ID of the key.

        Raises
        ------
        `ValueError`
            If neither name nor ID is specified.

        """
        if not name and not id:
            raise ValueError("Must specify name or ID")

        if id:
            info(f"Deleting key {id} from keychain")
            self.c.execute("DELETE FROM keys WHERE id = ?", (id,))
        else:
            info(f"Deleting key {name} from keychain")
            self.c.execute("DELETE FROM keys WHERE name = ?", (name,))

        self.conn.commit()

    def close(self) -> None:
        """Close the keychain connection."""
        self.conn.close()
