import sqlite3
from cryptlib.file_io import *


class keychain:
    """
    A class that manages the keychain database. The keychain database 
    stores public keys of other users
    """

    def __init__(self):
        conn = sqlite3.connect(
            f"{data_dir}/keychain.db")
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

        self.conn = conn
        self.c = c

    def add_key(self, name: str, key: bytes):
        """
        Adds a public key to the database
        """
        self.c.execute("INSERT INTO keys (name, key) VALUES (?, ?)",
                       (name, key))
        self.conn.commit()

    def get_key(self, name: str = None, id: int = None):
        """
        Gets a public key from the database
        """

        # Check if the user specified a name or id
        if not name and not id:
            raise ValueError("Must specify name or id")

        # Get the key using id or name
        if id:
            self.c.execute("SELECT key FROM keys WHERE id = ?", (id,))
            return self.c.fetchone()[0]
        self.c.execute("SELECT key FROM keys WHERE name = ?", (name,))
        return self.c.fetchone()[0]

    def get_names(self):
        """
        Gets all the names of the users whose public keys
        are saved in the database
        """
        self.c.execute("SELECT id, name FROM keys")
        return self.c.fetchall()

    def delete_key(self, name: str = None, id: int = None):
        """
        Deletes a public key from the database
        """

        # Check if the user specified a name or id
        if not name and not id:
            raise ValueError("Must specify name or id")

        # Delete the key using id or name
        if id:
            self.c.execute("DELETE FROM keys WHERE id = ?", (id,))
        self.c.execute("DELETE FROM keys WHERE name = ?", (name,))
        self.conn.commit()

    def close(self):
        """
        Closes the database connection
        """
        self.conn.close()
