from pathlib import Path
from shutil import copyfile
from typing import List, Optional

import typer
from password_strength import PasswordStats
from typing_extensions import Annotated

import cryptbuddy.commands.chain as chain
import cryptbuddy.commands.symmetric as symmetric
from cryptbuddy.lib.decrypt import asymmetric_decrypt
from cryptbuddy.lib.encrypt import asymmetric_encrypt
from cryptbuddy.lib.file_io import config_dir, shred_file, write_chunks
from cryptbuddy.lib.initialize import initialize_cryptbuddy
from cryptbuddy.lib.key_io import AppPrivateKey
from cryptbuddy.lib.keychain import Keychain
from cryptbuddy.lib.utils import error, info, success

app = typer.Typer(name="cryptbuddy", help="A CLI tool for encryption and decryption")
app.add_typer(chain.app, name="keychain", help="Manage your keychain")
app.add_typer(
    symmetric.app, name="symmetric", help="Encrypt and decrypt files symmetrically"
)
db = Keychain()


@app.command()
def init(
    name: Annotated[str, typer.Option("--name", "-u", help="Username")],
    email: Annotated[
        str, typer.Option("--email", "-e", prompt=True, confirmation_prompt=True)
    ],
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
        initialize_cryptbuddy(name, email, password)
    except Exception as e:
        error(e)
    success("Cryptbuddy initialized")


@app.command("shred")
def shred_cmd(
    paths: Annotated[
        List[Path],
        typer.Argument(
            help="Paths of the file(s) or folder(s) to be shredded",
            exists=True,
            readable=True,
            resolve_path=True,
        ),
    ],
):
    """Shreds files/folders such that they cannot be later recovered"""
    for path in paths:
        if path.is_dir():
            for file in path.rglob("*"):
                if file.is_file():
                    shred_file(file)
            path.rmdir()
            success(f"All files in {path} shredded")
        else:
            shred_file(path)
            success(f"{path} shredded")


# TODO: Export complete data with the key chain
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
    public_key_path = Path(f"{config_dir}/public.key")
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
            help="Paths of the file(s) and folder(s) to encrypt",
            exists=True,
            readable=True,
            writable=True,
            resolve_path=True,
        ),
    ],
    user: Annotated[Optional[List[str]], typer.Option("--user", "-u")] = None,
    shred: Annotated[
        bool,
        typer.Option("--shred", "-s", help="Shred the original file after encryption"),
    ] = True,
):
    """Encrypt file(s) or folder(s) for one or more users from your keychain"""
    if len(user) == 0:
        error("No users specified")

    for path in paths:
        if path.is_dir():
            for file in path.rglob("*"):
                suffix = file.suffix
                if file.is_file():
                    try:
                        chunks = asymmetric_encrypt(user, file)
                    except Exception as e:
                        error(e)
                    write_chunks(chunks, file.with_suffix(suffix + ".crypt"))
                    if shred:
                        shred_file(file)
                        info(f"{file} shredded")
                    success(f"{file} encrypted")
            success(f"All files in the {path} encrypted")
        else:
            try:
                chunks = asymmetric_encrypt(user, path)
            except Exception as e:
                error(e)
            suffix = path.suffix
            write_chunks(chunks, path.with_suffix(suffix + ".crypt"))
            if shred:
                shred_file(path)
                info(f"{path} shredded")
            success(f"{path} encrypted")


@app.command()
def decrypt(
    paths: Annotated[
        List[Path],
        typer.Argument(
            help="Path to the file to decrypt",
            exists=True,
            readable=True,
            writable=True,
            resolve_path=True,
        ),
    ],
    password: Annotated[
        str,
        typer.Option(
            "--password",
            "-p",
            prompt=True,
            hide_input=True,
            help="Password to decrypt your private key",
        ),
    ],
    shred: Annotated[
        bool,
        typer.Option("--shred", "-s", help="Shred the original file after decryption"),
    ] = True,
):
    """Decrypt file(s) or folder(s) encrypted with your public key"""
    private_key_path = Path(f"{config_dir}/private.key")
    if not private_key_path.exists():
        error("Private key not found. Please initialize CryptBuddy")

    private_key_object = AppPrivateKey.from_file(private_key_path)

    for path in paths:
        if path.is_dir():
            for file in path.rglob("*"):
                if file.is_file():
                    try:
                        chunks = asymmetric_decrypt(file, password, private_key_object)
                    except Exception as e:
                        error(e)

                    if file.suffix == ".crypt":
                        write_chunks(chunks, file.with_suffix(""))
                    else:
                        write_chunks(chunks, file.with_suffix(".dec"))
                    if shred:
                        shred_file(file)
                        info(f"{file} shredded")
                    success(f"{file} decrypted")
            success(f"All files in the {path} decrypted")
        else:
            try:
                chunks = asymmetric_decrypt(path, password, private_key_object)
            except Exception as e:
                error(e)
            if path.suffix == ".crypt":
                write_chunks(chunks, path.stem)
            else:
                write_chunks(chunks, path.with_suffix(".dec"))
            if shred:
                shred_file(path)
                info(f"{path} shredded")
            success(f"{path} decrypted")
