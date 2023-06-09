import base64
from pathlib import Path
from typing import List, Optional

import typer
from nacl.utils import random
from rich.progress import BarColumn, Progress, TimeElapsedColumn, TimeRemainingColumn
from typing_extensions import Annotated

from cryptbuddy.config import (
    CHUNKSIZE,
    CPUS,
    DATA_DIR,
    KEYSIZE,
    MACSIZE,
    MEM,
    NONCESIZE,
    OPS,
    SALTBYTES,
    SHRED,
)
from cryptbuddy.functions.file_io import get_decrypted_outfile, get_encrypted_outfile
from cryptbuddy.operations.asymmetric import asymmetric_decrypt, asymmetric_encrypt
from cryptbuddy.operations.concurrent_tasks import run
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
    cpus: Annotated[
        int,
        typer.Option(
            "--cpus",
            "-t",
            help="Number of CPUs to use for encryption",
        ),
    ] = CPUS,
):
    """
    Encrypt file(s) or folder(s) using a password or public keys of one or more
    users from your keychain
    """
    # symmetric encryption requires a password to generate a key
    # asymmetric encryption does not require a password,
    # but public keys of the recipents
    if symmetric and password is None:
        password = typer.prompt(
            "Password to encrypt the file", hide_input=True, confirmation_prompt=True
        )

    # we cannot pass arguments in the form of bytes, hence we use
    # base64 encoded strings
    bnonce = base64.b64decode(nonce)
    bsalt = base64.b64decode(salt)

    progress = Progress(
        "[progress.description]{task.description}",
        BarColumn(),
        "[progress.percentage]{task.percentage:>3.0f}%",
        TimeRemainingColumn(),
        TimeElapsedColumn(),
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

        # we can concurrently handle multiple paths using multiprocessing (cpus)
        run(
            progress=progress,
            paths=paths,
            op_type="encrypt",
            file_getter=get_encrypted_outfile,
            op_func=symmetric_encrypt,
            options=options,
            output=output,
            cpus=cpus,
        )

        success("File(s) encrypted.")
        return None

    if not symmetric and user:
        # for asymmetric encryption, we first generate a symmetric key
        # and encrypt it with the public keys of each of the recipents
        # the file is then encrypted symmetrically using the symmetric key
        # and the encrypted symmetric key is prepended to the file in
        # the form of a header (metadata)

        # public keys -> asymmetrically encrypt symmetric key
        # symmetric key -> symmetrically encrypts file data

        symkey = random(KEYSIZE)  # this is the symmetric key

        keychain = Keychain()
        public_keys = []
        for u in user:
            try:
                public_keys.append(keychain.get_key(u))
            except Exception as e:
                error(e)
                return None

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

        run(
            progress=progress,
            paths=paths,
            op_type="encrypt",
            file_getter=get_encrypted_outfile,
            op_func=asymmetric_encrypt,
            options=options,
            output=output,
            cpus=cpus,
        )

        success("File(s) encrypted.")
        return None

    error("Please specify either symmetric (with password) or users for encryption")
    return None


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
    cpus: Annotated[
        int,
        typer.Option(
            "--cpus",
            "-t",
            help="Number of CPUs to use for decryption",
        ),
    ] = CPUS,
):
    """
    Decrypt file(s) or folder(s) symmetrically using a password or
    asymmetrically using your private key
    """
    progress = Progress(
        "[progress.description]{task.description}",
        BarColumn(),
        "[progress.percentage]{task.percentage:>3.0f}%",
        TimeRemainingColumn(),
        TimeElapsedColumn(),
    )

    # password is required to generate the key in symmetric decryption
    if symmetric and password:
        options = SymmetricDecryptOptions(
            password=password,
            shred=shred,
        )

        run(
            progress=progress,
            paths=paths,
            op_type="decrypt",
            file_getter=get_decrypted_outfile,
            op_func=symmetric_decrypt,
            options=options,
            output=output,
            cpus=cpus,
        )

        success("File(s) decrypted.")

    # for asymmetric decryption, we need the private key
    # the private key is always encrypted with a password
    # so we need the password to decrypt the private key
    elif not symmetric and password:
        # usable private key
        private_key = AppPrivateKey.from_file(Path(f"{DATA_DIR}/private.key"), password)

        options = AsymmetricDecryptOptions(
            user=private_key.meta.name,
            password=password,
            private_key=private_key,
            shred=shred,
        )

        run(
            progress=progress,
            paths=paths,
            op_type="decrypt",
            file_getter=get_decrypted_outfile,
            op_func=asymmetric_decrypt,
            options=options,
            output=output,
            cpus=cpus,
        )

        success("File(s) decrypted.")
