from pathlib import Path
from typing import Optional

import typer
from typing_extensions import Annotated

from cryptbuddy.operations.logger import error, print_keys, success
from cryptbuddy.structs.app_keys import AppPublicKey
from cryptbuddy.structs.keychain import Keychain

app = typer.Typer(no_args_is_help=True, add_completion=True)
chain = Keychain()


@app.command()
def add(
    key: Annotated[
        Path,
        typer.Argument(
            help="Path to the public key",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            resolve_path=True,
        ),
    ]
):
    """Add a key to your keychain"""
    public_key = AppPublicKey.from_file(key)

    chain.add_key(public_key)
    success(f"{public_key.meta.name}'s public key added to the keychain")


@app.command()
def delete(
    name: Annotated[
        Optional[str],
        typer.Argument(help="Name of the user whose public key to delete"),
    ] = None,
    id: Annotated[
        Optional[int], typer.Option(help="ID of the public key to delete")
    ] = None,
):
    """Delete a key from your keychain"""
    if not name and not id:
        error("Please specify either name or ID")

    if id:
        chain.delete_key(id=id)
        success(f"Key with ID {id} deleted from the keychain")
    else:
        chain.delete_key(name=name)

    success(f"{name}'s public key deleted from the keychain")


@app.command("list")
def list_cmd():
    """List all the keys in your keychain"""
    keys = chain.get_names()
    print_keys(keys)
