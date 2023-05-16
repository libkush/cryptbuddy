import typer
from utils import *
from pathlib import Path
from typing import Optional
from typing_extensions import Annotated
from cryptlib.keychain import keychain
from cryptlib.key_io import AppPublicKey


app = typer.Typer()
chain = keychain()


@app.command()
def add(key: Annotated[Path, typer.Option(help="Public key file path")]):
    """
    Add a key to your keychain
    """
    public_key = AppPublicKey.from_file(key)
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
    if id:
        chain.delete_key(id=id)
        success(f"Key with ID {id} deleted from the keychain")
    else:
        chain.delete_key(name=name)
    success(f"{name}'s public key deleted from the keychain")


@app.command()
def list():
    """
    List all keys in your keychain
    """
    keys = chain.get_names()
    print_table(keys, [['ID', 'Name']])


if __name__ == "__main__":
    app()
