from typing import Optional

import typer
from password_strength import PasswordStats
from pkg_resources import get_distribution
from rich.progress import Progress, SpinnerColumn, TextColumn
from typing_extensions import Annotated

import cryptbuddy.commands.keychain as keychain
from cryptbuddy.commands.encryption import decrypt, encrypt
from cryptbuddy.commands.misc import export, shred_path
from cryptbuddy.operations.clean import clean
from cryptbuddy.operations.initialize import initialize
from cryptbuddy.operations.logger import error, warn

__version__ = get_distribution("cryptbuddy").version


app = typer.Typer(
    name="CryptBuddy",
    help="A CLI tool for encryption and decryption",
    add_completion=True,
    no_args_is_help=True,  # show help when no arguments are provided
    context_settings={"help_option_names": ["-h", "--help"]},  # add -h and --help
)


app.add_typer(keychain.app, name="keychain", help="Manage your keychain")


def version_callback(value: bool):
    """Callback for the --version option"""
    if value:
        print(f"CryptBuddy Version: {__version__}")
        raise typer.Exit()


@app.callback(no_args_is_help=True)
def common(
    # skipcq: PYL-W0613
    ctx: typer.Context,
    # skipcq: PYL-W0613
    version: bool = typer.Option(None, "--version", "-v", callback=version_callback),
):
    """A CLI tool for encryption and decryption"""


@app.command(no_args_is_help=True)
def init(
    name: Annotated[str, typer.Option("--name", "-u", help="Username")],
    email: Annotated[str, typer.Option("--email", "-e", prompt=True)],
    password: Annotated[
        str,
        typer.Option(
            "--password",
            "-p",
            prompt=True,
            confirmation_prompt=True,
            hide_input=True,
            help="Password to encrypt your private key",
        ),
    ],
    clean_dirs: Annotated[
        Optional[bool],
        typer.Option(
            "--clean",
            "-c",
            is_flag=True,
            help="Clean existing data before initializing",
        ),
    ] = False,
):
    """
    Initialize cryptbuddy by generating a key-pair and creating the
    keychain database
    """
    progress = Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        transient=False,
    )

    if clean_dirs:
        clean()

    stats = PasswordStats(password).strength()
    if stats < 0.3:
        warn("Password is too weak!", console=progress.console)

    progress.start()
    try:
        initialize(name, email, password, progress)
    except Exception as e:
        error(e, console=progress.console)
        clean()
    progress.stop()


app.command(no_args_is_help=True)(encrypt)

app.command(no_args_is_help=True)(decrypt)

app.command(no_args_is_help=True)(export)

app.command(no_args_is_help=True)(shred_path)

if __name__ == "__main__":
    app()
