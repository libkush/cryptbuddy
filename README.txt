CryptBuddy
~~~~~~~~~~

An over-engineered CLI program to perform multithreaded encryption/decryption.
This was written as an investigatory project for CBSE class XII board exams.

Whitepaper can be found at https://static.kush.in/projects/CryptBuddy.pdf

The CLI can be called using any of the commands 'cb', 'crypt', or 'cryptbuddy'

Usage: cb [OPTIONS] COMMAND [ARGS]...                                            
                                                                                  
 A CLI tool for encryption and decryption                                         
                                                                                  
╭─ Options ──────────────────────────────────────────────────────────────────────╮
│ --version             -v                                                       │
│ --install-completion            Install completion for the current shell.      │
│ --show-completion               Show completion for the current shell, to copy │
│                                 it or customize the installation.              │
│ --help                -h        Show this message and exit.                    │
╰────────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ─────────────────────────────────────────────────────────────────────╮
│ decrypt     Decrypt file(s) symmetrically using a password or asymmetrically   │
│             using your private key                                             │
│ encrypt     Encrypt file(s) using a password or public keys of one or more     │
│             users from your keychain                                           │
│ export      Export your public key file to specified directory to share with   │
│             others                                                             │
│ init        Initialize cryptbuddy by generating a key-pair and creating the    │
│             keychain database                                                  │
│ keychain    Manage your keychain                                               │
│ shred-path  Shred file(s) or directories                                       │
╰────────────────────────────────────────────────────────────────────────────────╯