import sqlite3
from typing import List, Tuple

from cryptbuddy.config import DATA_DIR
from cryptbuddy.structs.app_keys import AppPublicKey


class Keychain:
    """
    A keychain for storing public keys.

    Attributes
    ----------
    conn : sqlite3.Connection
        The connection to the database.
    c : sqlite3.Cursor
        The cursor for the database.

    Methods
    -------
    add_key(key: AppPublicKey)
        Adds a key to the keychain.
    get_key(name: str | None = None, id: int | None = None)
        Retrieves a key from the keychain.
    get_keys()
        Retrieves all keys from the keychain.
    remove_key(name: str | None = None, id: int | None = None)
        Removes a key from the keychain.
    """

    def __init__(self):
        conn = sqlite3.connect(f"{DATA_DIR}/keychain.db")
        c = conn.cursor()

        # Create the keys table if it doesn't exist
        create_query = """
            CREATE TABLE IF NOT EXISTS keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                key BLOB NOT NULL
            )
        """

        try:
            c.execute(create_query)
            conn.commit()
        except sqlite3.OperationalError:
            raise sqlite3.OperationalError("Unable to create keys table")

        # Set the connection and cursor attributes
        self.conn = conn
        self.c = c

    def add_key(self, key: AppPublicKey) -> None:
        """
        Add a key to the keychain.

        Parameters
        ----------
        key : cryptbuddy.structs.app_keys.AppPublicKey
            The key to be added.
        """
        self.c.execute(
            "INSERT INTO keys (name, key) VALUES (?, ?)", (key.meta.name, key.data)
        )
        self.conn.commit()

    def get_key(self, name: str | None = None, id: int | None = None) -> AppPublicKey:
        """
        Retrieve a key from the keychain.

        Parameters
        ----------
        name : str, optional
            The name of the key.
        id : int, optional
            The ID of the key.

        Returns
        -------
        cryptbuddy.structs.app_keys.AppPublicKey
            The key.
        """
        if not name and not id:
            raise ValueError("Must specify name or ID")

        if id:
            self.c.execute("SELECT key FROM keys WHERE id = ?", (id,))
        else:
            self.c.execute("SELECT key FROM keys WHERE name = ?", (name,))

        result = self.c.fetchone()
        if result is None:
            raise TypeError("Key not found")

        return AppPublicKey.from_data(result[0])

    def get_names(self) -> List[Tuple[int, str]]:
        """
        Retrieve all key names from the keychain.

        Returns
        -------
        List[Tuple[int, str]]
            A list of key names.
        """
        self.c.execute("SELECT id, name FROM keys")
        return self.c.fetchall()

    def delete_key(self, name: str | None = None, id: int | None = None) -> None:
        """
        Delete a key from the keychain.

        Parameters
        ----------
        name : str, optional
            The name of the key.
        id : int, optional
            The ID of the key.
        """
        if not name and not id:
            raise ValueError("Must specify name or ID")

        if id:
            self.c.execute("DELETE FROM keys WHERE id = ?", (id,))
        else:
            self.c.execute("DELETE FROM keys WHERE name = ?", (name,))

        self.conn.commit()

    def close(self) -> None:
        """Close the keychain connection."""
        self.conn.close()
