from pathlib import Path
from shutil import copyfile
from typing import List

import typer
from rich.console import Console
from typing_extensions import Annotated

from cryptbuddy.config import CONFIG_DIR
from cryptbuddy.functions.file_ops import shred as shred_file
from cryptbuddy.operations.logger import error, success


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
    console = Console()
    public_key_path = Path(f"{CONFIG_DIR}/public.key")
    if not public_key_path.exists():
        e = FileNotFoundError("Public key not found")
        return error(e, console=console)

    try:
        copyfile(public_key_path, Path(f"{directory}/public.key"))
    except Exception as e:
        return error(e, console=console)

    return success("File exported.", console=console)


def shred_path(
    paths: Annotated[
        List[Path],
        typer.Argument(
            exists=True,
            readable=True,
            writable=True,
            resolve_path=True,
            help="Paths of the file(s) and directories to shred",
        ),
    ],
):
    """Shred file(s) or directories"""
    console = Console()
    # shredding works by overwriting the file with random data
    # and then deleting it. this way, the file is unrecoverable
    for path in paths:
        shred_file(path)

    return success("File(s) shredded.", console=console)
