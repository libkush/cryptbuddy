import subprocess
from pathlib import Path

import pytest

from tests.utils import *

subprocess.run(["poetry", "install"], cwd=test_dir.parent)


@pytest.mark.parametrize("password", ["R@nd0m5h1t"])
@pytest.mark.parametrize("message", ["All sloths are slow"])
def test_symmetric_singlefile(message, password):
    file, fname = make_singlefile(message, test_dir, "test_file.txt")

    try:
        # Encryption
        encrypt_command = [
            "cb",
            "symmetric",
            "encrypt",
            str(file),
            "--password",
            password,
        ]
        encrypt_result = subprocess.run(
            encrypt_command, capture_output=True, text=True, cwd=test_dir
        )

        # Print the encryption stdout and stderr
        print_result(encrypt_result)

        # Assert the encryption return code and check for success message
        assert encrypt_result.returncode == 0
        assert "SUCCESS" in encrypt_result.stdout

        # Delete the original file after encryption
        if file.exists():
            file.unlink()

        # Decryption
        encrypted_file = file.with_suffix(file.suffix + ".crypt")
        decrypt_command = [
            "cb",
            "symmetric",
            "decrypt",
            str(encrypted_file),
            "--password",
            password,
        ]
        decrypt_result = subprocess.run(
            decrypt_command, capture_output=True, text=True, cwd=test_dir
        )

        # Print the decryption stdout and stderr
        print_result(decrypt_result)

        # Assert the decryption return code and check for success message
        assert decrypt_result.returncode == 0
        assert "SUCCESS" in decrypt_result.stdout

        # Verify the decrypted file contents
        decrypted_contents = Path(test_dir, fname).read_text()
        expected_contents = "All sloths are slow"
        assert decrypted_contents == expected_contents

    finally:
        # Clean up both the original and encrypted files
        if file.exists():
            file.unlink()
        if encrypted_file.exists():
            encrypted_file.unlink()


@pytest.mark.parametrize("password", ["R@nd0m5h1t"])
def test_symmetric_directory(password):
    dir1, file1, file2 = make_test_dir(test_dir, "test_file1.txt", "test_file2.txt")

    try:
        # Encryption
        encrypt_command = [
            "cb",
            "symmetric",
            "encrypt",
            str(dir1),
            "--password",
            password,
        ]
        encrypt_result = subprocess.run(
            encrypt_command, capture_output=True, text=True, cwd=test_dir
        )

        # Print the encryption stdout and stderr
        print_result(encrypt_result)

        # Assert the encryption return code and check for success message
        assert encrypt_result.returncode == 0
        assert "SUCCESS" in encrypt_result.stdout
        assert "All files" in encrypt_result.stdout

        # Delete the original files after encryption
        for f in dir1.iterdir():
            if not f.suffix == ".crypt":
                f.unlink()

        # Decryption
        decrypt_command = [
            "cb",
            "symmetric",
            "decrypt",
            str(dir1),
            "--password",
            password,
        ]
        decrypt_result = subprocess.run(
            decrypt_command, capture_output=True, text=True, cwd=test_dir
        )

        # Print the decryption stdout and stderr
        print_result(decrypt_result)

        # Assert the decryption return code and check for success message
        assert decrypt_result.returncode == 0
        assert "SUCCESS" in decrypt_result.stdout
        assert "All files" in decrypt_result.stdout

        # Verify the decrypted file contents
        decrypted_contents1 = file1.read_text()
        decrypted_contents2 = file2.read_text()
        expected_contents1 = "cats and dogs"
        expected_contents2 = "dogs and cats"
        assert decrypted_contents1 == expected_contents1
        assert decrypted_contents2 == expected_contents2

    finally:
        # Clean up both the original and encrypted files
        if dir1.exists():
            delete_folder(dir1)


@pytest.mark.parametrize("password", ["R@nd0m5h1t"])
@pytest.mark.parametrize("message", ["All sloths are slow"])
def test_symmetric_multipath(message, password):
    dir1, file1, file2 = make_test_dir(test_dir, "test_file1.txt", "test_file2.txt")

    file, fname = make_singlefile(message, test_dir, "test_file.txt")

    try:
        # Encryption
        encrypt_command = [
            "cb",
            "symmetric",
            "encrypt",
            str(dir1),
            str(file),
            "--password",
            password,
        ]

        encrypt_result = subprocess.run(
            encrypt_command, capture_output=True, text=True, cwd=test_dir
        )

        # Print the encryption stdout and stderr
        print_result(encrypt_result)

        # Assert the encryption return code and check for success message
        assert encrypt_result.returncode == 0
        assert "SUCCESS" in encrypt_result.stdout
        assert "All files" in encrypt_result.stdout

        # Delete the original files after encryption
        for f in dir1.iterdir():
            if not f.suffix == ".crypt":
                f.unlink()
        if file.exists():
            file.unlink()

        encrypted_file = file.with_suffix(file.suffix + ".crypt")
        decrypt_command = [
            "cb",
            "symmetric",
            "decrypt",
            str(encrypted_file),
            str(dir1),
            "--password",
            password,
        ]
        decrypt_result = subprocess.run(
            decrypt_command, capture_output=True, text=True, cwd=test_dir
        )

        # Print the decryption stdout and stderr
        print_result(decrypt_result)

        # Assert the decryption return code and check for success message
        assert decrypt_result.returncode == 0
        assert "SUCCESS" in decrypt_result.stdout
        assert "All files" in decrypt_result.stdout

        # Verify the decrypted file contents
        decrypted_contents1 = file1.read_text()
        decrypted_contents2 = file2.read_text()
        decrypted_contents3 = file.read_text()
        expected_contents1 = "cats and dogs"
        expected_contents2 = "dogs and cats"
        expected_contents3 = message
        assert decrypted_contents1 == expected_contents1
        assert decrypted_contents2 == expected_contents2
        assert decrypted_contents3 == expected_contents3

    finally:
        # Clean up both the original and encrypted files
        if dir1.exists():
            delete_folder(dir1)
        if file.exists():
            file.unlink()


# Run the test
if __name__ == "__main__":
    pytest.main([__file__])
