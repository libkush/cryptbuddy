class ProgressState:
    def __init__(self):
        self.tasks = {}

    def add_task(self, task_id, completed=0, total=0):
        self.tasks[task_id] = {"completed": completed, "total": total}

    def update(self, task_id, completed=None, total=None):
        if completed is not None:
            self.tasks[task_id]["completed"] = completed
        if total is not None:
            self.tasks[task_id]["total"] = total

    def get(self, task_id):
        return self.tasks[task_id]

    def increment(self, task_id, completed=1):
        self.tasks[task_id]["completed"] += completed
