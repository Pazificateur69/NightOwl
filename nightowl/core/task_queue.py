"""Async task queue with priority and concurrency control."""

import asyncio
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Coroutine

logger = logging.getLogger("nightowl")


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass(order=True)
class Task:
    priority: int
    name: str = field(compare=False)
    coro: Coroutine = field(compare=False)
    status: TaskStatus = field(default=TaskStatus.PENDING, compare=False)
    result: Any = field(default=None, compare=False)
    error: str | None = field(default=None, compare=False)


class TaskQueue:
    """Async task queue with concurrency limiting."""

    def __init__(self, max_workers: int = 5):
        self.max_workers = max_workers
        self._queue: asyncio.PriorityQueue[Task] = asyncio.PriorityQueue()
        self._tasks: list[Task] = []
        self._semaphore = asyncio.Semaphore(max_workers)
        self._cancelled = False

    async def add_task(self, name: str, coro: Coroutine, priority: int = 5) -> Task:
        task = Task(priority=priority, name=name, coro=coro)
        self._tasks.append(task)
        await self._queue.put(task)
        return task

    async def _run_task(self, task: Task) -> None:
        async with self._semaphore:
            if self._cancelled:
                task.status = TaskStatus.CANCELLED
                return
            try:
                task.status = TaskStatus.RUNNING
                task.result = await task.coro
                task.status = TaskStatus.COMPLETED
            except Exception as e:
                task.status = TaskStatus.FAILED
                task.error = str(e)
                logger.error(f"Task '{task.name}' failed: {e}")

    async def process(self) -> list[Task]:
        workers = []
        while not self._queue.empty():
            task = await self._queue.get()
            workers.append(asyncio.create_task(self._run_task(task)))

        if workers:
            await asyncio.gather(*workers, return_exceptions=True)
        return self._tasks

    def cancel_all(self) -> None:
        self._cancelled = True
        for task in self._tasks:
            if task.status == TaskStatus.PENDING:
                task.status = TaskStatus.CANCELLED

    @property
    def pending_count(self) -> int:
        return sum(1 for t in self._tasks if t.status == TaskStatus.PENDING)

    @property
    def completed_count(self) -> int:
        return sum(1 for t in self._tasks if t.status == TaskStatus.COMPLETED)
