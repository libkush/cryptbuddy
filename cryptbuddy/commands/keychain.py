from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from typing_extensions import Annotated

from cryptbuddy.operations.logger import error, print_keys, success
from cryptbuddy.structs.app_keys import AppPublicKey
from cryptbuddy.structs.keychain import Keychain

app = typer.Typer(no_args_is_help=True, add_completion=True)
chain = Keychain()


@app.command(no_args_is_help=True)
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
    console = Console()
    public_key = AppPublicKey.from_file(key)
    chain.add_key(public_key)
    return success(
        f"{public_key.meta.name}'s public key added to the keychain",
        console=console,
    )


@app.command(no_args_is_help=True)
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
    console = Console()
    if not name and not id:
        e = ValueError("Please specify either name or ID")
        return error(e, console=console)
    if id:
        chain.delete_key(id=id)
        return success(f"Key with ID {id} deleted from the keychain", console=console)

    chain.delete_key(name=name)
    return success(f"{name}'s public key deleted from the keychain", console=console)


@app.command("list", no_args_is_help=True)
def list_cmd():
    """List all the keys in your keychain"""
    console = Console()
    keys = chain.get_names()
    print_keys(keys, console=console)
