from pathlib import Path
from shutil import copyfile
from typing import List, Optional

import typer
from password_strength import PasswordStats
from typing_extensions import Annotated

import cryptbuddy.commands.chain as chain
import cryptbuddy.commands.symmetric as symmetric
from cryptbuddy.lib.constants import *
from cryptbuddy.lib.decrypt import asymmetric_decrypt
from cryptbuddy.lib.encrypt import asymmetric_encrypt
from cryptbuddy.lib.file_io import config_dir, shred_file, write_chunks
from cryptbuddy.lib.initialize import initialize_cryptbuddy
from cryptbuddy.lib.key_io import AppPrivateKey
from cryptbuddy.lib.keychain import Keychain
from cryptbuddy.lib.utils import *

db = Keychain()
app = typer.Typer(name="cryptbuddy",
                  help="A CLI tool for encryption and decryption")
app.add_typer(chain.app, name="keychain", help="Manage your keychain")
app.add_typer(symmetric.app, name="symmetric",
              help="Encrypt and decrypt files symmetrically")


@app.command()
def init(name: Annotated[str, typer.Option(help="Username")],
         email: Annotated[str, typer.Option(prompt=True, confirmation_prompt=True)],
         password: Annotated[str, typer.Option(prompt=True, confirmation_prompt=True, hide_input=True, help="Password to encrypt your private key")]):
    """
    Initialize cryptbuddy by generating a key-pair and creating the keychain database
    """

    # Check password strength
    stats = PasswordStats(password).strength()
    if stats < 0.3:
        error("Password is too weak!")

    # Initialize cryptbuddy
    try:
        initialize_cryptbuddy(name, email, password)
    except Exception as e:
        error(e)
    success("Cryptbuddy initialized")


@app.command()
def shred(path: Annotated[Path, typer.Argument(
    help="Path of the file to be shredded",
    exists=True,
    readable=True,
    resolve_path=True
)],):
    """
    Shred a file such that it cannot be recovered
    """

    if path.is_dir():
        # Shred the directory
        for file in path.iterdir():
            if file.is_file():
                shred_file(file)
        path.rmdir()
        success("Directory shredded successfully")
        return

    # Shred the file
    shred_file(path)
    success("File shredded successfully")


@app.command()
def export(dir: Annotated[Path, typer.Argument(
    help="Directory to export the public key to",
    exists=True,
    writable=True,
    resolve_path=True,
    dir_okay=True,
    file_okay=False
)]):
    """
    Export your public key to share with others
    """

    # Check if public key exists
    public_key_path = Path(f"{config_dir}/public.key")
    if not public_key_path.exists():
        error("Public key not found")

    # Copy public key to specified directory
    try:
        copyfile(public_key_path, Path(f"{dir}/public.key"))
    except Exception as e:
        error(e)

    success("File exported successfully")


@app.command()
def encrypt(path: Annotated[Path, typer.Argument(
    help="Path of the file to encrypt",
    exists=True,
    readable=True,
    writable=True,
    resolve_path=True
)],
        user: Annotated[Optional[List[str]], typer.Option()] = None,):
    """
    Encrypt a file for one or more users in your keychain
    """
    if len(user) == 0:
        error("No users specified")

    if path.is_dir():
        # Encrypt the directory
        for file in path.iterdir():
            suffix = file.suffix
            if file.is_file():
                try:
                    chunks = asymmetric_encrypt(user, file)
                except Exception as e:
                    error(e)
                write_chunks(chunks, file.with_suffix(suffix+".crypt"))
                success(f"{file} encrypted")
        success(f"All files in the {path} encrypted")
        return

    # Encrypt the file
    try:
        chunks = asymmetric_encrypt(user, path)
    except Exception as e:
        error(e)

    suffix = path.suffix
    write_chunks(chunks, path.with_suffix(suffix+".crypt"))
    success(f"{path} encrypted")


@app.command()
def decrypt(path: Annotated[Path, typer.Argument(
    help="Path of the file to decrypt",
    exists=True,
    readable=True,
    writable=True,
    resolve_path=True)],

    password: Annotated[
        str, typer.Option(
        prompt=True, hide_input=True, help="Password to decrypt your private key")]
):
    """
    Decrypt a file using your private key
    """

    private_key_path = Path(f"{config_dir}/private.key")
    if not private_key_path.exists():
        error("Private key not found")

    # Get your private key object from config directory
    private_key_object = AppPrivateKey.from_file(
        private_key_path)

    if path.is_dir():
        # Decrypt the directory
        for file in path.iterdir():
            if file.is_file():
                try:
                    chunks = asymmetric_decrypt(
                        file, password, private_key_object)
                except Exception as e:
                    error(e)

                if file.suffix == ".crypt":
                    write_chunks(chunks, file.with_suffix(""))
                else:
                    write_chunks(chunks, file.with_suffix(".dec"))
                success(f"{file} decrypted")
        success(f"All files in the {path} decrypted")
        return

    # Decrypt the file
    try:
        chunks = asymmetric_decrypt(path, password, private_key_object)
    except Exception as e:
        error(e)

    # Write the decrypted chunks to a file
    if path.suffix == ".crypt":
        write_chunks(chunks, path.stem)
    else:
        write_chunks(chunks, path.with_suffix(".dec"))

    success(f"{path} decrypted")


if __name__ == "__main__":
    app()
