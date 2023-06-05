import concurrent.futures
import multiprocessing as mp
from pathlib import Path
from typing import Callable, List, NewType, Union

from rich.progress import Progress, TaskID

from cryptbuddy.structs.types import (
    AsymmetricDecryptOptions,
    AsymmetricEncryptOptions,
    SymmetricDecryptOptions,
    SymmetricEncryptOptions,
)

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
    with mp.Manager() as manager:
        state = manager.dict()
        overall_progress_task = progress.add_task("[green]Completed:")
        progress.start()
        with concurrent.futures.ProcessPoolExecutor(max_workers=cpus) as executor:
            for path in paths:
                out_path = file_getter(path, output)  # output file
                task_id = progress.add_task(
                    f"[cyan]{doing}: {path.name}", completed=0, total=0
                )
                state[task_id] = {"completed": 0, "total": 0}
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
            while (n_finished := sum([future.done() for future in futures])) < len(
                futures
            ):
                progress.update(
                    overall_progress_task, completed=n_finished, total=len(futures)
                )
                for task_id, update_data in state.items():
                    total = update_data["total"]
                    latest = update_data["completed"]
                    # update the progress bar for this task:
                    progress.update(
                        task_id,
                        completed=latest,
                        total=total,
                    )
            for future in futures:
                future.result()
