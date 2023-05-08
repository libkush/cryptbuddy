import typer
from nacl import secret
from pathlib import Path
from typing import Optional
from pwinput import pwinput
from appdirs import user_config_dir
from typing_extensions import Annotated
from password_strength import PasswordStats
from cryptlib.symmetric.encrypt import encrypt
from cryptlib.symmetric.decrypt import decrypt
from cryptlib.initialize import initialize_cryptbuddy

app = typer.Typer()
dir = user_config_dir("cryptbuddy")


class SymConfig:
    def __init__(self, chunksize, macsize):
        self.chunksize = chunksize
        self.macsize = macsize


@app.command()
def init():
    initialize_cryptbuddy()
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
                           fg=typer.colors.WHITE, bg=typer.colors.RED)
        typer.echo(warn)
    try:
        encrypt(file, password, SymConfig(
            64 * 1024, secret.SecretBox.MACBYTES))
    except Exception as e:
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
        decrypt(file, password, SymConfig(
            64 * 1024, secret.SecretBox.MACBYTES))
    except Exception as e:
        typer.echo(e)
        raise typer.Exit(1)
    typer.echo("Decrypted file saved")
    if replace:
        Path(file).unlink()


if __name__ == "__main__":
    app()
