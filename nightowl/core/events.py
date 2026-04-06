"""Event system for inter-component communication."""

import asyncio
import logging
from enum import Enum
from typing import Any, Callable

logger = logging.getLogger("nightowl")


class Event(str, Enum):
    SCAN_STARTED = "scan.started"
    SCAN_COMPLETED = "scan.completed"
    SCAN_FAILED = "scan.failed"
    SCAN_PAUSED = "scan.paused"
    MODULE_STARTED = "module.started"
    MODULE_COMPLETED = "module.completed"
    MODULE_FAILED = "module.failed"
    FINDING_DISCOVERED = "finding.discovered"
    STAGE_CHANGED = "stage.changed"
    CONFIRMATION_REQUIRED = "confirmation.required"
    PROGRESS_UPDATE = "progress.update"


class EventBus:
    """Per-scan event bus. Create a new instance per scan to avoid leaks."""

    def __init__(self):
        self._subscribers: dict[Event, list[Callable]] = {}

    def subscribe(self, event: Event, callback: Callable) -> None:
        if event not in self._subscribers:
            self._subscribers[event] = []
        self._subscribers[event].append(callback)

    def unsubscribe(self, event: Event, callback: Callable) -> None:
        if event in self._subscribers:
            self._subscribers[event] = [
                cb for cb in self._subscribers[event] if cb != callback
            ]

    async def emit(self, event: Event, data: Any = None) -> None:
        logger.debug(f"Event: {event.value} | {data}")
        for callback in self._subscribers.get(event, []):
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(event, data)
                else:
                    callback(event, data)
            except Exception as e:
                logger.error(f"Event handler error for {event}: {e}")

    def clear(self) -> None:
        self._subscribers.clear()
