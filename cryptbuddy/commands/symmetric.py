from pathlib import Path
from typing import Optional

import typer
from cryptbuddy.cryptlib.file_io import shred_file, write_chunks
from cryptbuddy.cryptlib.symmetric.decrypt import symmetric_decrypt
from cryptbuddy.cryptlib.symmetric.encrypt import symmetric_encrypt
from cryptbuddy.cryptlib.utils import *
from password_strength import PasswordStats
from typing_extensions import Annotated

app = typer.Typer()


@app.command()
def encrypt(path: Annotated[Path, typer.Argument(
    help="Path of the file/decrypt to encrypt",
    exists=True,
    readable=True,
    writable=True,
    resolve_path=True
)],
    password: Annotated[
    str, typer.Option(
        prompt=True, confirmation_prompt=True, hide_input=True, help="Password to encrypt the file")
],
        shred: Annotated[Optional[bool], typer.Option(help="Shred the original file after encryption")] = False):
    """
    Encrypt a file using a password
    """

    # Check password strength
    stats = PasswordStats(password).strength()
    if stats < 0.3:
        warning("Password is weak!")

    if path.is_dir():
        # Encrypt all files in directory
        for file in path.iterdir():
            if file.is_file():
                try:
                    chunks = symmetric_encrypt(file, password=password)
                    encrypted_path = file.with_suffix(".crypt")
                    write_chunks(chunks, encrypted_path)
                except Exception as e:
                    error(e)
                # Shred original file if specified
                if shred:
                    shred_file(file)
        success("All files in directory encrypted successfully")
        return

    # Encrypt file symmetrically
    try:
        chunks = symmetric_encrypt(path, password=password)
        encrypted_path = path.with_suffix(".crypt")
        write_chunks(chunks, encrypted_path)
    except Exception as e:
        error(e)
    success("File encrypted successfully")

    # Shred file if specified
    if shred:
        shred_file(path)


@app.command()
def decrypt(path: Annotated[Path, typer.Argument(
    help="Path of the file to decrypt",
    exists=True,
    readable=True,
    writable=True,
    resolve_path=True)],
    password: Annotated[
    str, typer.Option(
        prompt=True, hide_input=True, help="Password to decrypt the file")
],
        shred: Annotated[Optional[bool], typer.Option(help="Shred the encrypted file after decryption")] = False):
    """
    Decrypt a file using a password
    """

    if path.is_dir():
        # Decrypt all files in directory
        for file in path.iterdir():
            if file.is_file():
                try:
                    chunks = symmetric_decrypt(file, password)
                    if file.suffix == ".crypt":
                        decrypted_path = file.with_suffix("")
                        print(decrypted_path)
                    else:
                        decrypted_path = file.with_suffix(".dec")
                    write_chunks(chunks, decrypted_path)
                except Exception as e:
                    error(e)
                # Shred original file if specified
                if shred:
                    shred_file(file)
        success("All files in directory decrypted successfully")
        return

    # Decrypt file symmetrically
    try:
        chunks = symmetric_decrypt(path, password)
        if path.suffix == ".crypt":
            decrypted_path = path.with_suffix("")
        else:
            decrypted_path = path.with_suffix(".dec")
        write_chunks(chunks, decrypted_path)
    except Exception as e:
        error(e)
    success("File decrypted successfully")

    # Shred file if specified
    if shred:
        shred_file(path)


if __name__ == "__main__":
    app()
