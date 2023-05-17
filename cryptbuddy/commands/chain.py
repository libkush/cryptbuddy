from pathlib import Path
from typing import Optional

import typer
from cryptbuddy.cryptlib.key_io import AppPublicKey
from cryptbuddy.cryptlib.keychain import keychain
from cryptbuddy.cryptlib.utils import *
from typing_extensions import Annotated

app = typer.Typer()
chain = keychain()


@app.command()
def add(key: Annotated[Path, typer.Option(help="Public key file path")]):
    """
    Add a key to your keychain
    """
    if not key.exists():
        error("File not found")

    # Create the public key object from file
    public_key = AppPublicKey.from_file(key)

    # Add the packed key to the keychain
    chain.add_key(public_key.meta.name, public_key.packed)
    success(f"{public_key.meta.name}'s public key added to the keychain")


@app.command()
def delete(name: Annotated[Optional[str], typer.Option(help="Name of the user whose public key to delete")] = None,
           id: Annotated[Optional[int], typer.Option(help="ID of the public key to delete")] = None):
    """
    Delete a key from your keychain
    """
    if not name and not id:
        error("Please specify either name or ID")

    # Delete the key from the keychain
    if id:
        chain.delete_key(id=id)
        success(f"Key with ID {id} deleted from the keychain")
    else:
        chain.delete_key(name=name)

    success(f"{name}'s public key deleted from the keychain")


@app.command()
def list():
    """
    List all the keys in your keychain
    """
    # Get the names of all the keys
    keys = chain.get_names()

    # Print the table
    print_table(keys, [['ID', 'Name']])


if __name__ == "__main__":
    app()
