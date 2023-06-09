class ProgressState:
    """
    ProgressState is a class that holds the state
    of a progress bar between processes.
    """

    def __init__(self):
        self.tasks = {}

    def add_task(self, task_id, completed=0, total=10):
        """Adds a task to the progress bar."""
        self.tasks[task_id] = {
            "completed": completed,
            "total": total,
            "description": "",
        }

    def update(self, task_id, completed=None, total=None, description=None):
        """Updates the progress of a task."""
        if completed is not None:
            self.tasks[task_id]["completed"] = completed
        if total is not None:
            self.tasks[task_id]["total"] = total
        if description is not None:
            self.tasks[task_id]["description"] = description

    def get(self, task_id):
        """Gets the progress of a task."""
        return self.tasks[task_id]

    def increment(self, task_id, completed=1):
        """Increments the progress of a task."""
        self.tasks[task_id]["completed"] += completed

    def get_tasks(self):
        """Gets all the tasks."""
        return self.tasks.items()
