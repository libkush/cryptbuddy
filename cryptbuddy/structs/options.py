from typing import List

from nacl.pwhash.argon2i import kdf

from cryptbuddy.structs.app_keys import AppPrivateKey, AppPublicKey


class EncryptOptions:
    """
    Options for encryption.

    Attributes
    ----------
    nonce : bytes
        The nonce to be used for encryption.
    salt : bytes
        The salt to be used for encryption.
    keysize : int
        The size of the encryption key.
    macsize : int
        The size of the message authentication code.
    noncesize : int
        The size of the nonce.
    saltbytes : int
        The size of the salt.
    chunksize : int
        The size of each chunk to be encrypted.
    mem : int
        The amount of memory to be used for encryption.
    ops : int
        The number of operations to be used for encryption.
    shred : bool
        Whether to shred the file after encryption.
    """

    def __init__(
        self,
        nonce: bytes,
        salt: bytes,
        keysize: int,
        macsize: int,
        chunksize: int,
        mem: int,
        ops: int,
        shred: bool,
    ):
        self.keysize = keysize
        self.chunksize = chunksize
        self.macsize = macsize
        self.noncesize = len(nonce)
        self.saltbytes = len(salt)
        self.salt = salt
        self.nonce = nonce
        self.mem = mem
        self.ops = ops
        self.shred = shred


class DecryptOptions:
    """
    Options for decryption.

    Attributes
    ----------
    shred : bool
        Whether to shred the file after decryption.
    """

    def __init__(
        self,
        shred: bool,
    ):
        self.shred = shred


class SymmetricEncryptOptions(EncryptOptions):
    """
    Options for symmetric encryption.

    Attributes
    ----------
    type : str
        The type of encryption.
    key : bytes
        The encryption key.

    Parameters
    ----------
    password : str
        The password to be used for encryption.
    """

    def __init__(
        self,
        password: str,
        *args,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.type = "symmetric"
        self.key = kdf(
            self.keysize,
            password.encode(),
            self.salt,
            memlimit=self.mem,
            opslimit=self.ops,
        )


class SymmetricDecryptOptions(DecryptOptions):
    """
    Options for symmetric decryption.

    Attributes
    ----------
    type : str
        The type of encryption.
    password : str
        The password to be used for decryption.

    Methods
    -------
    get_key(salt: bytes, mem, ops, keysize)
        Returns the decryption key.

    Parameters
    ----------
    password : str
        The password to be used for decryption.
    """

    def __init__(
        self,
        password: str,
        *args,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.type = "symmetric"
        self.password = password

    def get_key(self, salt: bytes, mem, ops, keysize):
        """
        Returns the decryption key.

        Parameters
        ----------
        salt : bytes
            The salt to be used for decryption.
        mem : int
            The amount of memory to be used for decryption.
        ops : int
            The number of operations to be used for decryption.
        keysize : int
            The size of the decryption key.
        """
        return kdf(
            keysize,
            self.password.encode(),
            salt,
            memlimit=mem,
            opslimit=ops,
        )


class AsymmetricEncryptOptions(EncryptOptions):
    """
    Options for asymmetric encryption.

    Attributes
    ----------
    type : str
        The type of encryption.
    public_keys : List[cryptbuddy.structs.app_keys.AppPublicKey]
        The public keys to be used for encryption.
    symkey : bytes
        The symmetric key to be used for encryption.
    keysize : int
        The size of the symmetric key.

    Parameters
    ----------
    symkey : bytes
        The symmetric key to be used for encryption.
    public_keys : List[cryptbuddy.structs.app_keys.AppPublicKey]
        The public keys to be used for encryption.
    """

    def __init__(self, symkey: bytes, public_keys: List[AppPublicKey], *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.public_keys = public_keys
        self.symkey = symkey
        self.keysize = len(symkey)
        self.type = "asymmetric"


class AsymmetricDecryptOptions(DecryptOptions):
    """
    Options for asymmetric decryption.

    Attributes
    ----------
    type : str
        The type of encryption.
    private_key : cryptbuddy.structs.app_keys.AppPrivateKey
        The private key to be used for decryption.
    password : str
        The password to be used for decryption.
    user : str
        The user to be used for decryption.

    Parameters
    ----------
    private_key : cryptbuddy.structs.app_keys.AppPrivateKey
        The private key to be used for decryption.
    password : str
        The password to be used for decryption.
    user : str
        The user to be used for decryption.
    """

    def __init__(
        self, user: str, private_key: AppPrivateKey, password: str, *args, **kwargs
    ):
        super().__init__(*args, **kwargs)
        self.user = user
        self.password = password
        self.private_key = private_key
        self.type = "asymmetric"
