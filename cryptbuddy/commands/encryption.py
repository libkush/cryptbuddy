import base64
from pathlib import Path
from typing import List, Optional

import typer
from nacl.utils import random
from rich.progress import Progress, SpinnerColumn, TextColumn
from typing_extensions import Annotated

from cryptbuddy.config import (
    CHUNKSIZE,
    DATA_DIR,
    KEYSIZE,
    MACSIZE,
    MEM,
    NONCESIZE,
    OPS,
    SALTBYTES,
    SHRED,
)
from cryptbuddy.functions.file_ops import get_decrypted_outfile, get_encrypted_outfile
from cryptbuddy.operations.asymmetric import asymmetric_decrypt, asymmetric_encrypt
from cryptbuddy.operations.logger import error, success
from cryptbuddy.operations.symmetric import symmetric_decrypt, symmetric_encrypt
from cryptbuddy.structs.app_keys import AppPrivateKey
from cryptbuddy.structs.keychain import Keychain
from cryptbuddy.structs.options import (
    AsymmetricDecryptOptions,
    AsymmetricEncryptOptions,
    SymmetricDecryptOptions,
    SymmetricEncryptOptions,
)


def encrypt(
    paths: Annotated[
        List[Path],
        typer.Argument(
            exists=True,
            readable=True,
            writable=True,
            file_okay=True,
            resolve_path=True,
            help="Paths of the file(s) to encrypt",
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
            help=f"{NONCESIZE}-bit Base64 encoded nonce",
        ),
    ] = base64.b64encode(random(NONCESIZE)).decode("utf-8"),
    salt: Annotated[
        str,
        typer.Option(
            "--salt",
            "-l",
            help=f"{SALTBYTES}-bit Base64 encoded salt",
        ),
    ] = base64.b64encode(random(SALTBYTES)).decode("utf-8"),
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
    Encrypt file(s) using a password or public keys of one or more
    users from your keychain
    """
    # symmetric encryption requires a password to generate a key
    # asymmetric encryption does not require a password,
    # but public keys of the recipents
    if symmetric and password is None:
        password = typer.prompt(
            "Password to encrypt the file", hide_input=True, confirmation_prompt=True
        )

    # we can't pass arguments in the form of bytes, hence we use
    # base64 encoded strings
    bnonce = base64.b64decode(nonce)
    bsalt = base64.b64decode(salt)

    progress = Progress(
        TextColumn("{task.description}"),
        SpinnerColumn(spinner_name="point", finished_text="done"),
        transient=True,
    )
    progress.start()
    overall_progress_task = progress.add_task(
        "[green]Encrypting files:", total=len(paths)
    )

    if symmetric and password:
        options = SymmetricEncryptOptions(
            mem=MEM,
            ops=OPS,
            macsize=MACSIZE,
            keysize=KEYSIZE,
            password=password,
            nonce=bnonce,
            salt=bsalt,
            chunksize=chunksize,
            shred=shred,
        )
        for path in paths:
            out_path = get_encrypted_outfile(path, output)
            symmetric_encrypt(
                path,
                options,
                out_path,
                max_partsize=300 * 1024 * 1024,
                progress=progress,
            )
            progress.advance(overall_progress_task)
        success("File(s) encrypted.", console=progress.console)
        return progress.stop()

    if not symmetric and user:
        # for asymmetric encryption, we first generate a random
        # key and use it to encrypt the file symmetrically, then
        # we encrypt the key with the public keys of each of
        # the recipents
        #
        # the encrypted symmetric key is prepended to the file in
        # the form of a header (metadata)
        #
        # public keys -> asymmetrically encrypt symmetric key
        # symmetric key -> symmetrically encrypts file data
        symkey = random(KEYSIZE)  # this is the generated key
        keychain = Keychain()
        public_keys = []
        for u in user:
            try:
                public_keys.append(keychain.get_key(u))
            except Exception as e:
                return error(e, console=progress.console)

        options = AsymmetricEncryptOptions(
            keysize=KEYSIZE,
            macsize=MACSIZE,
            mem=MEM,
            ops=OPS,
            symkey=symkey,
            public_keys=public_keys,
            nonce=bnonce,
            salt=bsalt,
            chunksize=chunksize,
            shred=shred,
        )
        for path in paths:
            out_path = get_encrypted_outfile(path, output)
            asymmetric_encrypt(path, options, out_path, max_partsize=300 * 1024 * 1024)
            progress.advance(overall_progress_task)
        success("File(s) encrypted.", console=progress.console)
        return progress.stop()
    e = ValueError(
        "Please specify either symmetric (with password) or users for encryption"
    )
    return error(e, console=progress.console)


def decrypt(
    paths: Annotated[
        List[Path],
        typer.Argument(
            exists=True,
            readable=True,
            writable=True,
            resolve_path=True,
            help="Paths of the file(s) to decrypt",
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
    Decrypt file(s) symmetrically using a password or
    asymmetrically using your private key
    """
    progress = Progress(
        TextColumn("{task.description}"),
        SpinnerColumn(spinner_name="point", finished_text="done"),
        transient=True,
    )
    progress.start()
    overall_progress_task = progress.add_task(
        "[green]Decrypting files:",
        total=len(paths),
    )

    # password is required to generate the key in symmetric decryption
    if symmetric and password:
        options = SymmetricDecryptOptions(
            password=password,
            shred=shred,
        )
        for path in paths:
            out_path = get_decrypted_outfile(path, output)
            symmetric_decrypt(
                path,
                options,
                out_path,
                max_partsize=300 * 1024 * 1024,
                progress=progress,
            )
            progress.advance(overall_progress_task)
        success("File(s) decrypted.", console=progress.console)
        return progress.stop()

    # for asymmetric decryption, we need the private key
    # the private key is always encrypted with user's password
    # so we need the password to decrypt the private key
    if not symmetric and password:
        # usable (decrypted) private key
        private_key = AppPrivateKey.from_file(Path(f"{DATA_DIR}/private.key"), password)

        options = AsymmetricDecryptOptions(
            user=private_key.meta.name,
            password=password,
            private_key=private_key,
            shred=shred,
        )
        for path in paths:
            out_path = get_decrypted_outfile(path, output)
            asymmetric_decrypt(
                path,
                options,
                out_path,
                max_partsize=300 * 1024 * 1024,
                progress=progress,
            )
            progress.advance(overall_progress_task)
        success("File(s) decrypted.", console=progress.console)
        return progress.stop()
    return None
