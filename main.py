import typer
import chain
import symmetric
from utils import *
from pathlib import Path
from typing import Optional
from pwinput import pwinput
from shutil import copyfile
from typing_extensions import Annotated
from password_strength import PasswordStats
from cryptlib.file_io import shred_file, config_dir
from cryptlib.initialize import initialize_cryptbuddy


app = typer.Typer()
app.add_typer(chain.app, name="keychain")
app.add_typer(symmetric.app, name="symmetric")


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
