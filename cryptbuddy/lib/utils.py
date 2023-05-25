import typer
from rich.table import Table
from rich.console import Console
from typing import Iterable, List, Tuple


def success(*args: object):
    """
    Prints a success message with green color and bold formatting.

    Parameters
    ----------
    *args : `object`
        The message or objects to be displayed as the success message.

    Returns
    -------
    `None`

    """
    # Convert arguments to a space-separated string
    msg = " ".join(str(arg) for arg in args)
    success = typer.style(f"SUCCESS: {msg}", fg=typer.colors.GREEN, bold=True)
    typer.echo(success)


def warning(*args: object):
    """
    Prints a warning message with yellow color and bold formatting.

    Parameters
    ----------
    *args : `object`
        The message or objects to be displayed as the warning message.

    Returns
    -------
    `None`

    """
    # Convert arguments to a space-separated string
    msg = " ".join(str(arg) for arg in args)
    warning = typer.style(f"WARNING: {msg}", fg=typer.colors.YELLOW, bold=True)
    typer.echo(warning)


def error(*args: object):
    """
    Prints an error message with red color and bold formatting, and raises a `typer.Exit` exception.

    Parameters
    ----------
    *args : `object`
        The message or objects to be displayed as the error message.

    Returns
    -------
    `None`

    Raises
    ------
    `typer.Exit`
        Always raises a `typer.Exit` exception with exit code 1.

    """
    # Convert arguments to a space-separated string
    msg = " ".join(str(arg) for arg in args)
    error = typer.style(f"ERROR: {msg}", fg=typer.colors.RED, bold=True)
    typer.echo(error)
    raise typer.Exit(1)


def info(*args):
    """
    Prints an informational message with blue color.

    Parameters
    ----------
    *args : `object`
        The message or objects to be displayed as the informational message.

    Returns
    -------
    `None`

    """
    # Convert arguments to a space-separated string
    msg = " ".join(str(arg) for arg in args)
    info = typer.style(f"INFO: {msg}", fg=typer.colors.BLUE)
    typer.echo(info)


def print_keys(records: List[Tuple[int, str]]):
    """
    Prints a table with the provided records using the tabulate library.

    Parameters
    ----------
    records : `List[Tuple[int, str]])`
        An iterable containing the records to be displayed in the table.

    Returns
    -------
    `None`

    """
    console = Console()
    table = Table(show_header=True, header_style="bold magenta")

    table.add_column("ID")
    table.add_column("Name")
    for record in records:
        table.add_row(str(record[0]), record[1])

    console.print(table)
