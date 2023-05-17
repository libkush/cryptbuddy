import typer
from tabulate import tabulate


def success(msg: str):
    """
    Print a success message
    """
    success = typer.style(f"SUCCESS: {msg}", fg=typer.colors.GREEN, bold=True)
    typer.echo(success)


def warning(msg: str):
    """
    Print a warning message
    """
    warning = typer.style(f"WARNING: {msg}", fg=typer.colors.YELLOW, bold=True)
    typer.echo(warning)


def error(msg: str):
    """
    Print an error message
    """
    error = typer.style(f"ERROR: {msg}", fg=typer.colors.RED, bold=True)
    typer.echo(error)
    raise typer.Exit(1)


def print_table(records, table_data):
    """
    Print a table
    """
    for record in records:
        table_data.append(list(record))
    table = tabulate(table_data, headers="firstrow", tablefmt="fancy_grid")
    typer.echo(table)
