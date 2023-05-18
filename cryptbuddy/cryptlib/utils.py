import typer
from tabulate import tabulate


def success(msg: str):
    """
    Display a success message.

    Args:
        msg (str): The success message.

    """
    success = typer.style(f"SUCCESS: {msg}", fg=typer.colors.GREEN, bold=True)
    typer.echo(success)


def warning(msg: str):
    """
    Display a warning message.

    Args:
        msg (str): The warning message.

    """
    warning = typer.style(f"WARNING: {msg}", fg=typer.colors.YELLOW, bold=True)
    typer.echo(warning)


def error(msg: str):
    """
    Display an error message and raise a typer.Exit exception.

    Args:
        msg (str): The error message.

    """
    error = typer.style(f"ERROR: {msg}", fg=typer.colors.RED, bold=True)
    typer.echo(error)
    raise typer.Exit(1)


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
