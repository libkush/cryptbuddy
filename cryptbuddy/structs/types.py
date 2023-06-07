class ProgressState:
    def __init__(self):
        self.tasks = {}

    def add_task(self, task_id, completed=0, total=10):
        self.tasks[task_id] = {
            "completed": completed,
            "total": total,
            "description": "",
        }

    def update(self, task_id, completed=None, total=None, description=None):
        if completed is not None:
            self.tasks[task_id]["completed"] = completed
        if total is not None:
            self.tasks[task_id]["total"] = total
        if description is not None:
            self.tasks[task_id]["description"] = description

    def get(self, task_id):
        return self.tasks[task_id]

    def increment(self, task_id, completed=1):
        self.tasks[task_id]["completed"] += completed

    def get_tasks(self):
        return self.tasks.items()
