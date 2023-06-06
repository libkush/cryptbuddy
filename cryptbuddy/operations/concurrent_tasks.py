import concurrent.futures
from multiprocessing.managers import BaseManager
from pathlib import Path
from time import sleep
from typing import Callable, List, NewType, Union

from rich.progress import Progress, TaskID

from cryptbuddy.structs.key_types import (
    AsymmetricDecryptOptions,
    AsymmetricEncryptOptions,
    SymmetricDecryptOptions,
    SymmetricEncryptOptions,
)
from cryptbuddy.structs.types import ProgressState

OptionsBase = (
    Union[
        SymmetricDecryptOptions,
        SymmetricEncryptOptions,
        AsymmetricDecryptOptions,
        AsymmetricEncryptOptions,
    ],
)

Options = NewType("Options", OptionsBase)


def run(
    progress: Progress,
    paths: List[Path],
    type: str,
    file_getter: Callable[[Path, Path], Path],
    op_func: Callable[[Path, Options, Path, dict, TaskID], None],
    options: Options,
    output: Path,
    cpus: int,
):
    futures = []
    doing = (
        "Encrypting"
        if type == "encrypt"
        else "Decrypting"
        if type == "decrypt"
        else "Processing"
    )
    BaseManager.register("ProgressState", ProgressState)
    manager = BaseManager()
    manager.start()
    state: ProgressState = manager.ProgressState()

    overall_progress_task = progress.add_task("[green]Completed:")
    progress.start()
    with concurrent.futures.ProcessPoolExecutor(max_workers=cpus) as executor:
        for path in paths:
            out_path = file_getter(path, output)  # output file
            task_id = progress.add_task(
                f"[cyan]{doing}: {path.name}", completed=0, total=0
            )
            state.add_task(task_id)
            futures.append(
                executor.submit(
                    op_func,
                    path,
                    options,
                    out_path,
                    state,
                    task_id,
                )
            )
        while (n_finished := sum([future.done() for future in futures])) < len(futures):
            progress.update(
                overall_progress_task, completed=n_finished, total=len(futures)
            )
            for task, value in state.get_tasks():
                total = value["total"]
                completed = value["completed"]
                progress.update(task, completed=completed, total=total)
        progress.update(
            overall_progress_task, completed=len(futures), total=len(futures)
        )
        for future in futures:
            future.result()
    progress.stop()
