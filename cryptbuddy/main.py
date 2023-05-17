from pathlib import Path
from shutil import copyfile
from typing import List, Optional

import typer
from password_strength import PasswordStats
from typing_extensions import Annotated

import cryptbuddy.commands.chain as chain
import cryptbuddy.commands.symmetric as symmetric
from cryptbuddy.cryptlib.constants import *
from cryptbuddy.cryptlib.decrypt import asymmetric_decrypt
from cryptbuddy.cryptlib.encrypt import asymmetric_encrypt
from cryptbuddy.cryptlib.file_io import config_dir, shred_file, write_chunks
from cryptbuddy.cryptlib.initialize import initialize_cryptbuddy
from cryptbuddy.cryptlib.key_io import AppPrivateKey
from cryptbuddy.cryptlib.keychain import keychain
from cryptbuddy.cryptlib.utils import *

db = keychain()
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
def shred(file: Annotated[Path, typer.Option(help="Path of the file to shred")]):
    """
    Shred a file such that it cannot be recovered
    """
    if not file.exists():
        error("File not found")

    # Shred the file
    shred_file(file)
    success("File shredded successfully")


@app.command()
def export(dir: Annotated[Path, typer.Option(help="Directory to copy the public key")]):
    """
    Export your public key to share with others
    """
    if not (dir.exists() or dir.is_dir()):
        error("Directory not found")

    # Copy public key to specified directory
    try:
        copyfile(Path(f"{config_dir}/public.key"), Path(f"{dir}/public.key"))
    except Exception as e:
        error(e)

    success("File exported successfully")


@app.command()
def encrypt(file: Annotated[Path, typer.Option(help="Path of the file to encrypt")],
            user: Annotated[Optional[List[str]], typer.Option()] = None,):
    """
    Encrypt a file for one or more users in your keychain
    """
    if len(user) == 0:
        error("No users specified")

    # Encrypt the file
    try:
        chunks = asymmetric_encrypt(user, file)
    except Exception as e:
        error(e)

    write_chunks(chunks, Path(f"{file}.enc"))
    success("File encrypted successfully")


@app.command()
def decrypt(file: Annotated[Path, typer.Option(help="Path of the file to decrypt")],
            password: Annotated[
            str, typer.Option(
                prompt=True, confirmation_prompt=True, hide_input=True, help="Password to decrypt your private key")
            ],):
    """
    Decrypt a file using your private key
    """

    if not file.exists():
        error("File not found")
    private_key_path = Path(f"{config_dir}/private.key")
    if not private_key_path.exists():
        error("Private key not found")

    # Get your private key object from config directory
    private_key_object = AppPrivateKey.from_file(
        private_key_path)

    # Decrypt the file
    try:
        chunks = asymmetric_decrypt(file, password, private_key_object)
    except Exception as e:
        error(e)

    write_chunks(chunks, Path(str(file)+".dec"))
    success("File decrypted successfully")


if __name__ == "__main__":
    app()
