from typing import List, Tuple

from ormsgpack import packb, unpackb


def add_meta(
    meta: dict, data: List[bytes], delimiter: bytes, esc: bytes
) -> List[bytes]:
    """
    Writes the given metadata and data to a file.

    ### Parameters
    - `meta` (`dict`): The metadata to be written.
    - `data` (`List[bytes]`): The data to be written.

    ### Returns
    `List[bytes]`: The metadata prepended to the data.

    """
    packed_meta = packb(meta).replace(delimiter, esc + delimiter)
    data.insert(0, delimiter)
    data.insert(0, packed_meta)
    return data


def parse_data(data: bytes, delimiter: bytes, esc: bytes) -> Tuple[dict, bytes]:
    """
    Parses the given data into metadata and data.

    ### Parameters
    - `data` (`bytes`): The data to be parsed.

    ### Returns
    `dict`: The metadata.
    `bytes`: The data.

    ### Raises
    - `ValueError`: If the delimiter is not found or is preceded by an escape sequence.

    """
    delimiter_index = data.find(delimiter)

    while (
        delimiter_index > 0
        and data[delimiter_index - len(esc) : delimiter_index] == esc
    ):
        # The delimiter is part of the packed meta, search for the next occurrence
        delimiter_index = data.find(delimiter, delimiter_index + 1)

    if delimiter_index == -1:
        raise ValueError("Delimiter not found or preceded by escape sequence")

    packed_meta = data[:delimiter_index].replace(esc + delimiter, delimiter)
    meta: dict = unpackb(packed_meta)

    out_data = data[delimiter_index + len(delimiter) :]

    return meta, out_data


def divide_in_chunks(data: bytes, chunk_size: int) -> List[bytes]:
    """
    Divides the given data into chunks of the given size.

    ### Parameters
    - `data` (`bytes`): The data to be divided.
    - `chunk_size` (`int`): The size of each chunk.

    ### Returns
    `List[bytes]`: The data divided into chunks.

    """
    return [data[i : i + chunk_size] for i in range(0, len(data), chunk_size)]
