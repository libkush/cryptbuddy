from nacl import pwhash, secret

"""
Cryptographic constants required by cryptbuddy
"""
KDF = pwhash.argon2i.kdf

CHUNKSIZE = 64 * 1024
MACSIZE = secret.SecretBox.MACBYTES
OPS = pwhash.argon2i.OPSLIMIT_SENSITIVE
MEM = pwhash.argon2i.MEMLIMIT_SENSITIVE
KEYSIZE = secret.SecretBox.KEY_SIZE
SALTBYTES = pwhash.argon2i.SALTBYTES
NONCESIZE = secret.SecretBox.NONCE_SIZE
ALL = (KDF, OPS, MEM,
       KEYSIZE, CHUNKSIZE, MACSIZE)
DELIMITER = b'\xFF\xFF\xFF\xFF'
ESCAPE_SEQUENCE = b'\xAA\xAA\xAA\xAA'
