import typer
from pathlib import Path
from typing import Optional
from pwinput import pwinput
from cryptlib.file_io import shred_file
from typing_extensions import Annotated
from password_strength import PasswordStats
from cryptlib.file_io import write_chunks
from cryptlib.initialize import initialize_cryptbuddy
from cryptlib.symmetric.encrypt import symmetric_encrypt
from cryptlib.symmetric.decrypt import symmetric_decrypt
app = typer.Typer()


def success(msg: str):
    """Print a success message"""
    success = typer.style(f"SUCCESS: {msg}", fg=typer.colors.GREEN, bold=True)
    typer.echo(success)


def warning(msg: str):
    """Print a warning message"""
    warning = typer.style(f"WARNING: {msg}", fg=typer.colors.YELLOW, bold=True)
    typer.echo(warning)


def error(msg: str):
    """Print an error message"""
    error = typer.style(f"ERROR: {msg}", fg=typer.colors.RED, bold=True)
    typer.echo(error)
    raise typer.Exit(1)


@app.command()
def init(name: Annotated[str, typer.Option()],
         email: Annotated[str, typer.Option()],
         password: Annotated[Optional[str], typer.Option()] = None):
    """Initialize cryptbuddy by generating a key-pair and creating the keychain database"""

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
def symencrypt(file: Annotated[Path, typer.Option()],
               password: Annotated[Optional[str], typer.Option()] = None,
               shred: Annotated[Optional[bool], typer.Option()] = False):
    """Encrypt a file using a password"""

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
def symdecrypt(file: Annotated[Path, typer.Option()],
               password: Annotated[Optional[str], typer.Option()] = None,
               shred: Annotated[Optional[bool], typer.Option()] = False):
    """Decrypt a file using a password"""

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
