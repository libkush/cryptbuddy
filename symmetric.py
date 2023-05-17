import typer
from cryptlib.utils import *
from pathlib import Path
from pwinput import pwinput
from typing import Optional
from typing_extensions import Annotated
from password_strength import PasswordStats
from cryptlib.file_io import shred_file, write_chunks
from cryptlib.symmetric.encrypt import symmetric_encrypt
from cryptlib.symmetric.decrypt import symmetric_decrypt

app = typer.Typer()


@app.command()
def encrypt(file: Annotated[Path, typer.Option(help="Path of the file to encrypt")],
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
        chunks = symmetric_encrypt(file, password=password)
        encrypted_path = Path(f"{file}.enc")
        write_chunks(chunks, encrypted_path)
    except Exception as e:
        error(e)
    success("File encrypted successfully")

    # Shred file if specified
    if shred:
        shred_file(file)


@app.command()
def decrypt(file: Annotated[Path, typer.Option(help="Path of the file to decrypt")],
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


if __name__ == "__main__":
    app()