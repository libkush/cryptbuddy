import base64
from pathlib import Path
from shutil import copyfile
from typing import List, Optional

import typer
from nacl.utils import random
from password_strength import PasswordStats
from pkg_resources import get_distribution
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.style import Style
from typing_extensions import Annotated

import cryptbuddy.commands.keychain as chain
from cryptbuddy.config import *
from cryptbuddy.functions.file_io import (
    get_decrypted_outfile,
    get_encrypted_outfile,
    shred,
    untar_directory,
)
from cryptbuddy.operations.asymmetric import asymmetric_decrypt, asymmetric_encrypt
from cryptbuddy.operations.clean import clean
from cryptbuddy.operations.initialize import initialize
from cryptbuddy.operations.logging import error, success
from cryptbuddy.operations.symmetric import symmetric_decrypt, symmetric_encrypt
from cryptbuddy.structs.app_keys import AppPrivateKey
from cryptbuddy.structs.keychain import Keychain
from cryptbuddy.structs.types import (
    AsymmetricDecryptOptions,
    AsymmetricEncryptOptions,
    SymmetricDecryptOptions,
    SymmetricEncryptOptions,
)

__version__ = get_distribution("cryptbuddy").version


app = typer.Typer(
    name="CryptBuddy",
    help="A CLI tool for encryption and decryption",
    add_completion=True,
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)
app.add_typer(chain.app, name="keychain", help="Manage your keychain")


def version_callback(value: bool):
    """Callback for the --version option"""
    if value:
        print(f"CryptBuddy Version: {__version__}")
        raise typer.Exit()


@app.callback()
def common(
    ctx: typer.Context,
    version: bool = typer.Option(None, "--version", "-v", callback=version_callback),
):
    """A CLI tool for encryption and decryption"""
    pass


@app.command()
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
        error("Password is too weak!")

    progress.start()
    try:
        initialize(name, email, password, progress)
    except Exception as e:
        error(e)
    progress.stop()


@app.command()
def export(
    directory: Annotated[
        Path,
        typer.Argument(
            help="Directory to export the public key to",
            exists=True,
            writable=True,
            resolve_path=True,
            dir_okay=True,
            file_okay=False,
        ),
    ]
):
    """Export your public key file to specified directory to share with others"""
    public_key_path = Path(f"{CONFIG_DIR}/public.key")
    if not public_key_path.exists():
        error("Public key not found")

    try:
        copyfile(public_key_path, Path(f"{directory}/public.key"))
    except Exception as e:
        error(e)

    success("File exported successfully")


@app.command()
def encrypt(
    paths: Annotated[
        List[Path],
        typer.Argument(
            exists=True,
            readable=True,
            writable=True,
            resolve_path=True,
            help="Paths of the file(s) and folder(s) to encrypt",
        ),
    ],
    symmetric: Annotated[
        Optional[bool],
        typer.Option(
            "--symmetric", "-s", help="Encrypt file symmetrically using a password"
        ),
    ] = False,
    user: Annotated[
        Optional[List[str]],
        typer.Option(
            "--user",
            "-u",
            help="Encrypt a file asymmetrically for user(s). Password is not required",
        ),
    ] = None,
    password: Annotated[
        Optional[str],
        typer.Option(
            "--password",
            "-p",
            help="""
            Password to encrypt the file symmetrically. If not provided, 
            you will be prompted to enter the password
            """,
        ),
    ] = None,
    output: Annotated[
        Optional[Path],
        typer.Option(
            "--output",
            "-o",
            resolve_path=True,
            exists=True,
            file_okay=False,
            dir_okay=True,
            writable=True,
            help="Output directory to store the encrypted file(s)",
        ),
    ] = None,
    nonce: Annotated[
        str,
        typer.Option(
            "--nonce",
            "-n",
            help="Base64 encoded nonce value used to encrypt the file",
        ),
    ] = base64.b64encode(random(NONCESIZE)).decode("utf-8"),
    salt: Annotated[
        str,
        typer.Option(
            "--salt",
            "-l",
            help="Base64 encoded salt to encrypt the file",
        ),
    ] = base64.b64encode(random(SALTBYTES)).decode("utf-8"),
    keysize: Annotated[
        int,
        typer.Option(
            "--keysize",
            "-k",
            help="Key size for the generated symmetric keys",
        ),
    ] = KEYSIZE,
    macsize: Annotated[
        int,
        typer.Option(
            "--macsize",
            "-m",
            help="MAC size to encrypt the file",
        ),
    ] = MACSIZE,
    chunksize: Annotated[
        int,
        typer.Option(
            "--chunksize",
            "-c",
            help="Size of the chunks to break the file into for encryption",
        ),
    ] = CHUNKSIZE,
    shred: Annotated[
        Optional[bool],
        typer.Option(
            "--shred/--no-shred",
            "-d",
            help="Whether to shred the original file after encryption",
        ),
    ] = SHRED,
):
    """
    Encrypt file(s) or folder(s) using a password or public keys of one or more
    users from your keychain
    """

    if symmetric and password is None:
        password = typer.prompt(
            "Password to encrypt the file", hide_input=True, confirmation_prompt=True
        )

    bnonce = base64.b64decode(nonce)
    bsalt = base64.b64decode(salt)

    progress = Progress(
        SpinnerColumn(),
        TextColumn("{task.description}[progress.description]"),
        BarColumn(
            style=Style(color="red"),
            complete_style=Style(color="green"),
        ),
    )

    if symmetric and password:
        options = SymmetricEncryptOptions(
            mem=MEM,
            ops=OPS,
            password=password,
            nonce=bnonce,
            salt=bsalt,
            keysize=keysize,
            macsize=macsize,
            chunksize=chunksize,
            shred=shred,
        )
        progress.start()
        for path in paths:
            encrypted_path = get_encrypted_outfile(path, output)
            try:
                symmetric_encrypt(path, options, encrypted_path, progress)
            except Exception:
                continue
        progress.stop()
        success("File(s) encrypted successfully")
        return None

    if not symmetric and user:
        keychain = Keychain()
        public_keys = []
        symkey = random(keysize)
        for u in user:
            try:
                public_keys.append(keychain.get_key(u))
            except Exception as e:
                error(e)
                return None
        options = AsymmetricEncryptOptions(
            symkey=symkey,
            public_keys=public_keys,
            nonce=bnonce,
            salt=bsalt,
            keysize=keysize,
            macsize=macsize,
            chunksize=chunksize,
            shred=shred,
            mem=MEM,
            ops=OPS,
        )
        progress.start()
        for path in paths:
            encrypted_path = get_encrypted_outfile(path, output)
            try:
                asymmetric_encrypt(path, options, encrypted_path, progress)
            except Exception:
                continue
        progress.stop()
        success("File(s) encrypted successfully")
        return None

    error("Please specify either symmetric (with password) or users for encryption")
    return None


@app.command()
def decrypt(
    paths: Annotated[
        List[Path],
        typer.Argument(
            exists=True,
            readable=True,
            writable=True,
            resolve_path=True,
            help="Paths of the file(s) and folder(s) to decrypt",
        ),
    ],
    password: Annotated[
        str,
        typer.Option(
            "--password",
            "-p",
            prompt=True,
            hide_input=True,
            help="""
            Password to decrypt the file if encrypted symmetrically, 
            or to decrypt your private key if encrypted asymmetrically
            """,
        ),
    ],
    symmetric: Annotated[
        Optional[bool],
        typer.Option(
            "--symmetric", "-s", help="Decrypt the file symmetrically using a password"
        ),
    ] = False,
    shred: Annotated[
        Optional[bool],
        typer.Option(
            "--shred/--no-shred",
            "-d",
            help="Whether to shred the original file after decryption",
        ),
    ] = SHRED,
    output: Annotated[
        Optional[Path],
        typer.Option(
            "--output",
            "-o",
            resolve_path=True,
            exists=True,
            file_okay=False,
            dir_okay=True,
            writable=True,
            help="Output directory to store the decrypted file(s)",
        ),
    ] = None,
):
    """
    Decrypt file(s) or folder(s) symmetrically using a password or
    asymmetrically using your private key
    """

    progress = Progress(
        SpinnerColumn(),
        TextColumn("{task.description}[progress.description]"),
        BarColumn(
            style=Style(color="red"),
            complete_style=Style(color="green"),
        ),
    )

    if symmetric and password:
        options = SymmetricDecryptOptions(
            password=password,
            shred=shred,
        )
        progress.start()
        for path in paths:
            decrypted_path = get_decrypted_outfile(path, output)
            try:
                symmetric_decrypt(path, options, decrypted_path, progress)
            except Exception:
                continue
            if decrypted_path.exists() and decrypted_path.suffix == ".tar":
                untar_directory(decrypted_path, decrypted_path.parent, shred)
        progress.stop()
        success("File(s) decrypted successfully")

    elif not symmetric and password:
        private_key = AppPrivateKey.from_file(Path(f"{DATA_DIR}/private.key"), password)
        options = AsymmetricDecryptOptions(
            user=private_key.meta.name,
            password=password,
            private_key=private_key,
            shred=shred,
        )
        progress.start()
        for path in paths:
            decrypted_path = get_decrypted_outfile(path, output)
            try:
                asymmetric_decrypt(path, options, decrypted_path, progress)
            except Exception:
                continue
            if decrypted_path.exists() and decrypted_path.suffix == ".tar":
                untar_directory(decrypted_path, decrypted_path.parent, shred)
        progress.stop()
        success("File(s) decrypted successfully")


@app.command(name="shred")
def shred_path(
    paths: Annotated[
        List[Path],
        typer.Argument(
            exists=True,
            readable=True,
            writable=True,
            resolve_path=True,
            help="Paths of the file(s) and folder(s) to shred",
        ),
    ],
):
    """Shred file(s) or folder(s)"""

    for path in paths:
        shred(path)

    success("File(s) shredded successfully")
