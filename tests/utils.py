from pathlib import Path


def delete_folder(pth):
    for sub in pth.iterdir():
        if sub.is_dir():
            delete_folder(sub)
        else:
            sub.unlink()
    pth.rmdir()


def make_singlefile(message, pth, fname):
    file = Path(pth, fname)
    with open(file, 'w') as f:
        f.write(message)
    return file, fname


def print_result(result):
    print("=== STDOUT ===")
    print(result.stdout)
    print("=== STDERR ===")
    print(result.stderr)


def make_test_dir(test_dir, fname1, fname2):
    dir1 = Path(test_dir, 'dir1')
    file1 = Path(dir1, fname1)
    file2 = Path(dir1, fname2)

    dir1.mkdir()

    with open(file1, 'w') as f:
        f.write('cats and dogs')
    with open(file2, 'w') as f:
        f.write('dogs and cats')

    return dir1, file1, file2


test_dir = Path(Path(__file__).parent, '.cache')
test_dir.mkdir(exist_ok=True)
