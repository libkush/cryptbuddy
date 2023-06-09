import concurrent.futures
from multiprocessing.managers import BaseManager
from pathlib import Path
from typing import Callable, List, NewType, Union

from rich.progress import Progress, TaskID

from cryptbuddy.structs.options import (
    AsymmetricDecryptOptions,
    AsymmetricEncryptOptions,
    SymmetricDecryptOptions,
    SymmetricEncryptOptions,
)
from cryptbuddy.structs.types import ProgressState

# the options type is a union of all the options types
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
    op_type: str,  # will be encrypt or decrypt
    file_getter: Callable[
        [Path, Path], Path
    ],  # will be encrypted_file_getter or decrypted_file_getter
    op_func: Callable[
        [Path, Options, Path, dict, TaskID], None
    ],  # will be encrypt or decrypt operation
    options: Options,
    output: Path,
    cpus: int,
):
    """
    Runs the given operation on the given paths.

    ### Parameters
    - `progress` (`Progress`): The progress bar.
    - `paths` (`List[Path]`): The paths to the files or folders to be processed.
    - `type` (`str`): The type of operation to be performed.
    - `file_getter` (`Callable[[Path, Path], Path]`): The function
        to get the output file.
    - `op_func` (`Callable[[Path, Options, Path, dict, TaskID], None]`): The
        operation function.
    - `options` (`Options`): The options for the operation.
    - `output` (`Path`): The path to the output file.
    - `cpus` (`int`): The number of CPUs to use.
    """
    futures = []
    doing = (
        "Encrypting"
        if op_type == "encrypt"
        else "Decrypting"
        if op_type == "decrypt"
        else "Processing"
    )  # what we are doing

    # create a shared progress state object, this will be accessed
    # by all the processes to update the progress bar
    BaseManager.register("ProgressState", ProgressState)
    manager = BaseManager()
    manager.start()
    state: ProgressState = manager.ProgressState()

    # master progress bar for all files
    overall_progress_task = progress.add_task("[green]Completed:")
    progress.start()

    # run the operation on each file concurrently
    with concurrent.futures.ProcessPoolExecutor(max_workers=cpus) as executor:
        for path in paths:
            out_path = file_getter(path, output)  # output file

            # add a task for the file
            task_id = progress.add_task(
                f"[cyan]{doing}: {path.name}", completed=0, total=0
            )
            state.add_task(task_id)

            # submit the operation
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

        # while the futures are not all done, update the progress bar
        while (n_finished := sum([future.done() for future in futures])) < len(futures):
            progress.update(
                overall_progress_task, completed=n_finished, total=len(futures)
            )
            for task, value in state.get_tasks():
                total = value["total"]
                completed = value["completed"]
                description = value["description"]
                if description:
                    progress.update(
                        task, completed=completed, total=total, description=description
                    )
                else:
                    progress.update(task, completed=completed, total=total)
        progress.update(
            overall_progress_task, completed=len(futures), total=len(futures)
        )

        # get the results of the futures
        for future in futures:
            future.result()

    progress.stop()
