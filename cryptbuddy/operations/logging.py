from typing import Iterable, List, Tuple

from rich import console
from rich.progress import Progress, SpinnerColumn, TaskID, TextColumn, track
from rich.table import Table

process = Progress(
    SpinnerColumn(),
    TextColumn("[bold blue]{task.description}"),
    transient=True,
)


def print_keys(records: List[Tuple[int, str]]):
    table = Table(show_header=True, header_style="bold magenta")

    table.add_column("ID")
    table.add_column("Name")
    for record in records:
        table.add_row(str(record[0]), record[1])

    console.print(table)


def add_task(msg: str, total: int | None = None) -> TaskID:
    return process.add_task(description=msg, total=total)


def update_task(task_id: TaskID, msg: str):
    process.update(task_id, description=msg, advance=1)


def info(*msgs: object):
    process.console.print(f"[bold blue]", *msgs)


def error(*msgs: object):
    process.console.print(f"[bold red]", *msgs)


def success(*msgs: object):
    process.console.print(f"[bold green]", *msgs)


def start_process():
    process.start()


def stop_process():
    process.stop()
