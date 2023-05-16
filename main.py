import typer
import chain
from shutil import copyfile
from utils import *
from pathlib import Path
from typing import Optional
from pwinput import pwinput
from cryptlib.file_io import shred_file, write_chunks, config_dir
from typing_extensions import Annotated
from password_strength import PasswordStats
from cryptlib.initialize import initialize_cryptbuddy
from cryptlib.symmetric.encrypt import symmetric_encrypt
from cryptlib.symmetric.decrypt import symmetric_decrypt


app = typer.Typer()
app.add_typer(chain.app, name="keychain")


@app.command()
def init(name: Annotated[str, typer.Option(help="Full Name")],
         email: Annotated[str, typer.Option(help="Email Address")],
         password: Annotated[Optional[str], typer.Option(help="Password for encrypting private key")] = None):
    """
    Initialize cryptbuddy by generating a key-pair and creating the keychain database
    """

    if not password:
        password = pwinput("Enter password: ")

    # Check password strength
    stats = PasswordStats(password).strength()
    print(stats)
    if stats < 0.3:
        error("Password is too weak!")

    # Initialize cryptbuddy
    try:
        initialize_cryptbuddy(name, email, password)
    except Exception as e:
        error(e)
    success("Cryptbuddy initialized")


@app.command()
def symencrypt(file: Annotated[Path, typer.Option(help="Path of the file to encrypt")],
               password: Annotated[Optional[str], typer.Option(
                   help="Password for symmetric encryption")] = None,
               shred: Annotated[Optional[bool], typer.Option(help="Shred the original file after encryption")] = False):
    """
    Encrypt a file using a password
    """

    # Check if file exists
    if not file.exists():
        error("File not found")

    if not password:
        password = pwinput("Enter password: ")

    # Check password strength
    stats = PasswordStats(password).strength()
    if stats < 0.3:
        warning("Password is weak!")

    # Encrypt file symmetrically
    try:
        chunks = symmetric_encrypt(file, password)
        encrypted_path = Path(f"{file}.enc")
        write_chunks(chunks, encrypted_path)
    except Exception as e:
        error(e)
    success("File encrypted successfully")

    # Shred file if specified
    if shred:
        shred_file(file)


@app.command()
def symdecrypt(file: Annotated[Path, typer.Option(help="Path of the file to decrypt")],
               password: Annotated[Optional[str], typer.Option(
                   help="Password for symmetric decryption")] = None,
               shred: Annotated[Optional[bool], typer.Option(help="Shred the encrypted file after decryption")] = False):
    """
    Decrypt a file using a password
    """

    # Check if file exists
    if not file.exists():
        error("File not found")

    if not password:
        password = pwinput("Enter password: ")

    # Decrypt file symmetrically
    try:
        chunks = symmetric_decrypt(file, password)
        decrypted_path = Path(f"{file}.dec")
        write_chunks(chunks, decrypted_path)
    except Exception as e:
        error(e)
    success("File decrypted successfully")

    # Shred file if specified
    if shred:
        shred_file(file)


@app.command()
def shred(file: Annotated[Path, typer.Option(help="Path of the file to shred")]):
    """
    Shred a file
    """
    if not file.exists():
        error("File not found")
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


if __name__ == "__main__":
    app()
