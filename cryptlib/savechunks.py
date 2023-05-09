from pathlib import Path


def savetofile(chunks, path: Path):
    with open(path, "wb") as outfile:
        for chunk in chunks:
            outfile.write(chunk)
