import typer
from nacl import secret
from pathlib import Path
from typing import Optional
from pwinput import pwinput
from appdirs import user_config_dir
from typing_extensions import Annotated
from password_strength import PasswordStats
from cryptlib.savechunks import savetofile
from cryptlib.initialize import initialize_cryptbuddy
from cryptlib.symmetric.encrypt import symmetric_encrypt
from cryptlib.symmetric.decrypt import symmetric_decrypt

app = typer.Typer()
dir = user_config_dir("cryptbuddy")


class SymConfig:
    def __init__(self, chunksize, macsize):
        self.chunksize = chunksize
        self.macsize = macsize


@app.command()
def init(password: Annotated[Optional[str], typer.Option()] = None):
    if not password:
        password = pwinput("Enter password: ")
    stats = PasswordStats(password).strength()
    if stats < 0.66:
        error = typer.style("ERROR: Password is too weak!",
                            fg=typer.colors.RED, bold=True)
        typer.echo(error)
        raise typer.Exit(1)
    initialize_cryptbuddy(password, dir)
    typer.echo("Generated private key")


@app.command()
def symncrypt(file: Annotated[Path, typer.Option()], password: Annotated[Optional[str], typer.Option()] = None, replace: Annotated[Optional[bool], typer.Option()] = False):
    if not Path(file).is_file():
        typer.echo("File not found")
        raise typer.Exit(1)
    if not password:
        password = pwinput("Enter password: ")
    stats = PasswordStats(password).strength()
    if stats < 0.66:
        warn = typer.style("WARNING: Password is too weak!",
                           fg=typer.colors.YELLOW, bold=True)
        typer.echo(warn)
    try:
        chunks = symmetric_encrypt(file, password, SymConfig(
            64 * 1024, secret.SecretBox.MACBYTES))
        encrypted_path = Path(f"{file}.enc")
        savetofile(chunks, encrypted_path)
    except Exception as e:
        e = typer.style(e, fg=typer.colors.RED, bold=True)
        typer.echo(e)
        raise typer.Exit(1)
    typer.echo("Encrypted file saved")
    if replace:
        Path(file).unlink()


@app.command()
def symdcrypt(file: Annotated[Path, typer.Option()], password: Annotated[Optional[str], typer.Option()] = None, replace: Annotated[Optional[bool], typer.Option()] = False):
    if not Path(file).is_file():
        typer.echo("File not found")
        raise typer.Exit(1)
    if not password:
        password = pwinput("Enter password: ")
    try:
        chunks = symmetric_decrypt(file, password, SymConfig(
            64 * 1024, secret.SecretBox.MACBYTES))
        decrypted_path = Path(f"{file}.dec")
        savetofile(chunks, decrypted_path)
    except Exception as e:
        e = typer.style(e, fg=typer.colors.RED, bold=True)
        typer.echo(e)
        raise typer.Exit(1)
    typer.echo("Decrypted file saved")
    if replace:
        Path(file).unlink()


# @app.command()
# def asymncrypt(file: Annotated[Path, typer.Option()], replace: Annotated[Optional[bool], typer.Option()] = False):
#     if not Path(file).is_file():
#         typer.echo("File not found")
#         raise typer.Exit(1)
#     pivateKey = Path(f"{dir}/private.key.enc")
#     if not pivateKey.is_file():
#         typer.echo("Private key not found. Please run 'cryptbuddy init' first")
#         raise typer.Exit(1)
#     try:
if __name__ == "__main__":
    app()
