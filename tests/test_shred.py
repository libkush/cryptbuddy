from pathlib import Path
import subprocess
import pytest

test_dir = Path(__file__).parent

subprocess.run(["poetry", "install"], cwd=test_dir.parent)


def test_shred_singlefile():
    fname = 'test_file.txt'
    file = Path(test_dir, fname)
    with open(file, 'w') as f:
        f.write('All sloths are slow')
    try:
        shred_command = ["cb", "shred", str(file)]
        shred_result = subprocess.run(
            shred_command, capture_output=True, text=True, cwd=test_dir)
        print("=== SHRED STDOUT ===")
        print(shred_result.stdout)
        print("=== SHRED STDERR ===")
        print(shred_result.stderr)
        assert shred_result.returncode == 0
        assert "SUCCESS" in shred_result.stdout
    finally:
        if file.exists():
            file.unlink()


def delete_folder(pth):
    for sub in pth.iterdir():
        if sub.is_dir():
            delete_folder(sub)
        else:
            sub.unlink()
    pth.rmdir()


def test_shred_directory():
    dir1 = Path(test_dir, 'dir1')
    fname1 = 'test_file1.txt'
    fname2 = 'test_file2.txt'
    file1 = Path(dir1, fname1)
    file2 = Path(dir1, fname2)

    dir1.mkdir()
    with open(file1, 'w') as f:
        f.write('All sloths are slow')
    with open(file2, 'w') as f:
        f.write('All sloths are slow again')

    try:
        shred_command = ["cb", "shred", str(dir1)]
        shred_result = subprocess.run(
            shred_command, capture_output=True, text=True, cwd=test_dir)
        print("=== SHRED STDOUT ===")
        print(shred_result.stdout)
        print("=== SHRED STDERR ===")
        print(shred_result.stderr)
        assert shred_result.returncode == 0
        assert "SUCCESS" in shred_result.stdout
    finally:
        if dir1.exists():
            delete_folder(dir1)


# Run the test
if __name__ == '__main__':
    pytest.main([__file__])
