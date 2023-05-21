import typer
from tabulate import tabulate


def success(*args: object):
    """
    Display a success message.

    Args:
        *args (object): The success message(s).

    """
    msg = " ".join(str(arg) for arg in args)
    success = typer.style(f"SUCCESS: {msg}", fg=typer.colors.GREEN, bold=True)
    typer.echo(success)


def warning(*args: object):
    """
    Display a warning message.

    Args:
        *args (object): The warning message(s).

    """
    msg = " ".join(str(arg) for arg in args)
    warning = typer.style(f"WARNING: {msg}", fg=typer.colors.YELLOW, bold=True)
    typer.echo(warning)


def error(*args: object):
    """
    Display an error message and raise a typer.Exit exception.

    Args:
        *args (object): The error message(s).

    """
    msg = " ".join(str(arg) for arg in args)
    error = typer.style(f"ERROR: {msg}", fg=typer.colors.RED, bold=True)
    typer.echo(error)
    raise typer.Exit(1)


def info(*args):
    """
    Display an info message.

    Args:
        *args (object): The info message(s).

    """
    msg = " ".join(str(arg) for arg in args)
    info = typer.style(f"INFO: {msg}", fg=typer.colors.BLUE)
    typer.echo(info)


def print_table(records, table_data):
    """
    Print tabular data in a formatted table.

    Args:
        records: The records to be displayed in the table.
        table_data: The data structure containing the table data.

    """
    for record in records:
        table_data.append(list(record))

    table = tabulate(table_data, headers="firstrow", tablefmt="fancy_grid")
    typer.echo(table)
