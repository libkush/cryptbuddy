from pathlib import Path
import subprocess
import pytest

test_dir = Path(__file__).parent
user = "Kush Patel"

subprocess.run(["poetry", "install"], cwd=test_dir.parent)


@pytest.mark.parametrize("password", ["R@nd0m5h1t"])
def test_asymmetric_singlefile(password):
    fname = 'test_file.txt'
    file = Path(test_dir, fname)
    with open(file, 'w') as f:
        f.write('All sloths are slow')

    try:
        # Encryption
        encrypt_command = ["cb", "encrypt", str(file), "--user", f"{user}"]
        encrypt_result = subprocess.run(
            encrypt_command, capture_output=True, text=True, cwd=test_dir)

        # Print the encryption stdout and stderr
        print("=== ENCRYPTION STDOUT ===")
        print(encrypt_result.stdout)
        print("=== ENCRYPTION STDERR ===")
        print(encrypt_result.stderr)

        # Assert the encryption return code and check for success message
        assert encrypt_result.returncode == 0
        assert "SUCCESS" in encrypt_result.stdout

        # Delete the original file after encryption
        file.unlink()

        # Decryption
        encrypted_file = file.with_suffix(file.suffix+'.crypt')
        decrypt_command = ["cb", "decrypt", str(
            encrypted_file), "--password", password]
        decrypt_result = subprocess.run(
            decrypt_command, capture_output=True, text=True, cwd=test_dir)

        # Print the decryption stdout and stderr
        print("=== DECRYPTION STDOUT ===")
        print(decrypt_result.stdout)
        print("=== DECRYPTION STDERR ===")
        print(decrypt_result.stderr)

        # Assert the decryption return code and check for success message
        assert decrypt_result.returncode == 0
        assert "SUCCESS" in decrypt_result.stdout

        # Verify the decrypted file contents
        decrypted_contents = Path(test_dir, fname).read_text()
        expected_contents = 'All sloths are slow'
        assert decrypted_contents == expected_contents

    finally:
        # Clean up both the original and encrypted files
        if file.exists():
            file.unlink()
        if encrypted_file.exists():
            encrypted_file.unlink()


def delete_folder(pth):
    for sub in pth.iterdir():
        if sub.is_dir():
            delete_folder(sub)
        else:
            sub.unlink()
    pth.rmdir()


@pytest.mark.parametrize("password", ["R@nd0m5h1t"])
def test_asymmetric_directory(password):
    dir1 = Path(test_dir, 'dir1')
    fname1 = 'test_file1.txt'
    fname2 = 'test_file2.txt'
    file1 = Path(dir1, fname1)
    file2 = Path(dir1, fname2)

    dir1.mkdir()
    with open(file1, 'w') as f:
        f.write('cats and dogs')
    with open(file2, 'w') as f:
        f.write('dogs and cats')

    try:
        # Encryption
        encrypt_command = ["cb", "encrypt",
                           str(dir1), "--user", f"{user}"]
        encrypt_result = subprocess.run(
            encrypt_command, capture_output=True, text=True, cwd=test_dir)

        # Print the encryption stdout and stderr
        print("=== ENCRYPTION STDOUT ===")
        print(encrypt_result.stdout)
        print("=== ENCRYPTION STDERR ===")
        print(encrypt_result.stderr)

        # Assert the encryption return code and check for success message
        assert encrypt_result.returncode == 0
        assert "SUCCESS" in encrypt_result.stdout
        assert "All files" in encrypt_result.stdout

        # Delete the original files after encryption
        for f in dir1.iterdir():
            if not f.suffix == '.crypt':
                f.unlink()

        # Decryption
        decrypt_command = ["cb", "decrypt",
                           str(dir1), "--password", password]
        decrypt_result = subprocess.run(
            decrypt_command, capture_output=True, text=True, cwd=test_dir)

        # Print the decryption stdout and stderr
        print("=== DECRYPTION STDOUT ===")
        print(decrypt_result.stdout)
        print("=== DECRYPTION STDERR ===")
        print(decrypt_result.stderr)

        # Assert the decryption return code and check for success message
        assert decrypt_result.returncode == 0
        assert "SUCCESS" in decrypt_result.stdout
        assert "All files" in decrypt_result.stdout

        # Verify the decrypted file contents
        decrypted_contents1 = file1.read_text()
        decrypted_contents2 = file2.read_text()
        expected_contents1 = 'cats and dogs'
        expected_contents2 = 'dogs and cats'
        assert decrypted_contents1 == expected_contents1
        assert decrypted_contents2 == expected_contents2

    finally:
        # Clean up both the original and encrypted files
        if dir1.exists():
            delete_folder(dir1)

        # Run the test
if __name__ == '__main__':
    pytest.main([__file__])
