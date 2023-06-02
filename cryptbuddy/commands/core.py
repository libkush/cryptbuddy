import base64
from pathlib import Path
from shutil import copyfile
from typing import List, Optional

import typer
from nacl.utils import random
from password_strength import PasswordStats
from pkg_resources import get_distribution
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
    name="cryptbuddy",
    help="A CLI tool for encryption and decryption",
    add_completion=True,
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)
app.add_typer(chain.app, name="keychain", help="Manage your keychain")


def version_callback(value: bool):
    if value:
        print(f"CryptBuddy Version: {__version__}")
        raise typer.Exit()


@app.callback()
def common(
    ctx: typer.Context,
    version: bool = typer.Option(None, "--version", callback=version_callback),
):
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
):
    """
    Initialize cryptbuddy by generating a key-pair and creating the
    keychain database
    """
    stats = PasswordStats(password).strength()
    if stats < 0.3:
        error("Password is too weak!")

    try:
        initialize(name, email, password)
    except Exception as e:
        error(e)
    success("Cryptbuddy initialized")


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
    symmetric: Annotated[Optional[bool], typer.Option("--symmetric", "-s")] = False,
    user: Annotated[Optional[List[str]], typer.Option("--user", "-u")] = None,
    password: Annotated[
        Optional[str],
        typer.Option(
            "--password",
            "-p",
            help="Password to encrypt the file",
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
            help="Output directory to store the encrypted file",
        ),
    ] = None,
    nonce: Annotated[
        str,
        typer.Option(
            "--nonce",
            "-n",
            help="Nonce to encrypt the file",
        ),
    ] = base64.b64encode(random(NONCESIZE)).decode("utf-8"),
    salt: Annotated[
        str,
        typer.Option(
            "--salt",
            "-l",
            help="Salt to encrypt the file",
        ),
    ] = base64.b64encode(random(SALTBYTES)).decode("utf-8"),
    keysize: Annotated[
        int,
        typer.Option(
            "--keysize",
            "-k",
            help="Key size to encrypt the file",
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
            help="Chunk size to encrypt the file",
        ),
    ] = CHUNKSIZE,
    shred: Annotated[
        Optional[bool],
        typer.Option(
            "--shred/--no-shred",
            "-d",
            help="Shred the original file after encryption",
        ),
    ] = SHRED,
):
    """Encrypt file(s) or folder(s) for one or more users from your keychain"""

    if symmetric and password is None:
        password = typer.prompt(
            "Password to encrypt the file", hide_input=True, confirmation_prompt=True
        )

    bnonce = base64.b64decode(nonce)
    bsalt = base64.b64decode(salt)

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
        for path in paths:
            encrypted_path = get_encrypted_outfile(path, output)
            symmetric_encrypt(path, options, encrypted_path)
        return success("File(s) encrypted successfully")

    if not symmetric and user:
        keychain = Keychain()
        public_keys = []
        symkey = random(keysize)
        for u in user:
            try:
                public_keys.append(keychain.get_key(u))
            except Exception as e:
                error(e)
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
        for path in paths:
            encrypted_path = get_encrypted_outfile(path, output)
            asymmetric_encrypt(path, options, encrypted_path)
        return success("File(s) encrypted successfully")

    error(
        "Please specify either symmetric (with password) or asymmetric (with user) encryption"
    )


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
            help="Password to decrypt the file",
        ),
    ],
    symmetric: Annotated[Optional[bool], typer.Option("--symmetric", "-s")] = False,
    shred: Annotated[
        Optional[bool],
        typer.Option(
            "--shred/--no-shred",
            "-d",
            help="Shred the original file after decryption",
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
            help="Output directory to store the decrypted file",
        ),
    ] = None,
):
    """Decrypt file(s) or folder(s)"""

    if symmetric and password:
        options = SymmetricDecryptOptions(
            password=password,
            shred=shred,
        )
        for path in paths:
            decrypted_path = get_decrypted_outfile(path, output)
            symmetric_decrypt(path, options, decrypted_path)
            if decrypted_path.suffix == ".tar":
                untar_directory(decrypted_path, decrypted_path.parent, shred)
        success("File(s) decrypted successfully")

    elif not symmetric and password:
        private_key = AppPrivateKey.from_file(Path(f"{DATA_DIR}/private.key"), password)
        options = AsymmetricDecryptOptions(
            user=private_key.meta.name,
            password=password,
            private_key=private_key,
            shred=shred,
        )
        for path in paths:
            decrypted_path = get_decrypted_outfile(path, output)
            asymmetric_decrypt(path, options, decrypted_path)
            if decrypted_path.suffix == ".tar":
                untar_directory(decrypted_path, decrypted_path.parent, shred)
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