from pathlib import Path
from typing import Optional, List

import typer
from cryptbuddy.lib.file_io import shred_file, write_chunks
from cryptbuddy.lib.symmetric.decrypt import symmetric_decrypt
from cryptbuddy.lib.symmetric.encrypt import symmetric_encrypt
from cryptbuddy.lib.utils import *
from password_strength import PasswordStats
from typing_extensions import Annotated

app = typer.Typer()


@app.command()
def encrypt(paths: Annotated[List[Path], typer.Argument(
    help="Path to the file(s) or folder(s) to encrypt",
    exists=True,
    readable=True,
    writable=True,
    resolve_path=True
)],
    password: Annotated[
    str, typer.Option("--password", "-p",
                      prompt=True, confirmation_prompt=True, hide_input=True, help="Password to encrypt the file")
],
        shred: Annotated[Optional[bool], typer.Option("--shred", "-s", help="Shred the original file after encryption")] = True):
    """
    Encrypt file(s) or folder(s) using a password
    """

    stats = PasswordStats(password).strength()
    if stats < 0.3:
        warning("Password is weak!")

    for path in paths:

        if path.is_dir():
            for file in path.rglob("*"):
                if file.is_file():
                    suffix = file.suffix
                    try:
                        chunks = symmetric_encrypt(file, password=password)
                        encrypted_path = file.with_suffix(suffix+".crypt")
                        write_chunks(chunks, encrypted_path)
                    except Exception as e:
                        error(e)
                    success(f"{file} encrypted")
                    if shred:
                        shred_file(file)
                        info(f"{file} shredded")
            success(f"All files in {path} encrypted")

        else:
            try:
                chunks = symmetric_encrypt(path, password=password)
                encrypted_path = path.with_suffix(path.suffix+".crypt")
                write_chunks(chunks, encrypted_path)
            except Exception as e:
                error(e)
            success(f"{path} encrypted")

            if shred:
                shred_file(path)
                info(f"{path} shredded")


@app.command()
def decrypt(paths: Annotated[List[Path], typer.Argument(
    help="Path to the file(s) or folder(s) to decrypt",
    exists=True,
    readable=True,
    writable=True,
    resolve_path=True)],
    password: Annotated[
    str, typer.Option(
        prompt=True, hide_input=True, help="Password to decrypt the file")
],
        shred: Annotated[Optional[bool], typer.Option("--shred", "-s", help="Shred the encrypted file after decryption")] = True):
    """
    Decrypt file(s) or folder(s) using a password
    """

    for path in paths:

        if path.is_dir():
            for file in path.rglob("*"):
                if file.is_file():
                    try:
                        chunks = symmetric_decrypt(file, password)
                        if file.suffix == ".crypt":
                            decrypted_path = file.with_suffix("")
                        else:
                            decrypted_path = file.with_suffix(".dec")
                        write_chunks(chunks, decrypted_path)
                    except Exception as e:
                        error(e)
                    success(f"{file} decrypted")
                    if shred:
                        shred_file(file)
                        info(f"{file} shredded")
            success(f"All files in {path} decrypted")

        else:
            try:
                chunks = symmetric_decrypt(path, password)
                if path.suffix == ".crypt":
                    decrypted_path = path.with_suffix("")
                else:
                    decrypted_path = path.with_suffix(".dec")
                write_chunks(chunks, decrypted_path)
            except Exception as e:
                error(e)
            success(f"{path} decrypted")
            if shred:
                shred_file(path)
                info(f"{path} shredded")


if __name__ == "__main__":
    app()
