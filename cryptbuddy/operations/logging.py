import logging
from logging.handlers import RotatingFileHandler
from typing import List, Tuple

from rich.console import Console
from rich.progress import Progress, TaskID
from rich.table import Table
from rich.text import Text

from cryptbuddy.config import CACHE_DIR

console = Console()

error_handler = RotatingFileHandler(
    CACHE_DIR / "errors.log", maxBytes=1024, backupCount=5
)
error_handler.setLevel(logging.ERROR)
error_handler.setFormatter(
    logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
)
error_logger = logging.getLogger("cb_errors")
error_logger.setLevel(logging.ERROR)
error_logger.addHandler(error_handler)


def print_keys(records: List[Tuple[int, str]]):
    table = Table(show_header=True, header_style="bold magenta")

    table.add_column("ID")
    table.add_column("Name")
    for record in records:
        table.add_row(str(record[0]), record[1])

    console.print(table)


def info(*msgs: object):
    message = " ".join(str(msg) for msg in msgs)
    text = Text(message, style="bold blue")
    console.print(text)


def error(e: Exception, progress: Progress = None, task: TaskID = None):
    error_logger.exception(e, exc_info=True)
    message = str(e)
    text = Text(message, style="bold red")
    if progress and task:
        progress.update(
            task,
            description=f"[bold red]Error: {message}",
        )
    else:
        console.print(text)


def success(*msgs: object):
    message = " ".join(str(msg) for msg in msgs)
    text = Text(message, style="bold green")
    console.print(text)
