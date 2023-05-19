import sqlite3

from cryptbuddy.lib.file_io import *

create_directories()


class Keychain:
    """
    Represents a keychain that stores keys in an SQLite database.
    """

    def __init__(self):
        conn = sqlite3.connect(f"{data_dir}/keychain.db")
        c = conn.cursor()

        # Create the keys table if it doesn't exist
        create_query = '''
            CREATE TABLE IF NOT EXISTS keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                key BLOB NOT NULL
            )
        '''
        c.execute(create_query)
        conn.commit()

        # Set the connection and cursor attributes
        self.conn = conn
        self.c = c

    def add_key(self, name: str, key: bytes):
        """
        Add a key to the keychain.

        Args:
            name (str): The name associated with the key.
            key (bytes): The key to be added.

        """
        info(f"Adding key {name} to keychain")
        self.c.execute(
            "INSERT INTO keys (name, key) VALUES (?, ?)", (name, key))
        self.conn.commit()

    def get_key(self, name: str = None, id: int = None):
        """
        Retrieve a key from the keychain.

        Args:
            name (str): The name associated with the key.
            id (int): The ID of the key.

        Returns:
            bytes: The retrieved key.

        Raises:
            ValueError: If neither name nor ID is specified.
            TypeError: If the key with the specified name or ID does not exist.

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

        return result[0]

    def get_names(self):
        """
        Retrieve the names and IDs of all keys in the keychain.

        Returns:
            list: A list of tuples containing the ID and name of each key.

        """
        self.c.execute("SELECT id, name FROM keys")
        return self.c.fetchall()

    def delete_key(self, name: str = None, id: int = None):
        """
        Delete a key from the keychain.

        Args:
            name (str): The name associated with the key.
            id (int): The ID of the key.

        Raises:
            ValueError: If neither name nor ID is specified.

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

    def close(self):
        """
        Close the keychain connection.

        """
        self.conn.close()
