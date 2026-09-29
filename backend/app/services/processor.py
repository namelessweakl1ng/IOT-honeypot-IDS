import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

from ..config import get_settings
from .detector import detect
from .sessionizer import reconstruct_sessions
from .telemetry import SCHEMA_VERSION, is_internal_event

LOGGER = logging.getLogger(__name__)


class EventProcessor:
    """Small idempotent materializer: deterministic IDs plus ES upserts survive restarts."""

    def __init__(self, store: Any) -> None:
        self.store = store
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        self.last_run: str | None = None
        self.last_error: str | None = None
        self.sessions_written = 0
        self.detections_written = 0

    async def process_once(self) -> dict[str, int]:
        settings = get_settings()
        events = await self.store.search(
            "trapsig-events-*", size=settings.processing_event_limit, sort_field="@timestamp"
        )
        sessions = reconstruct_sessions(
            [event for event in events if not is_internal_event(event)],
            settings.session_timeout_seconds,
        )
        detections: list[dict[str, Any]] = []
        for session in sessions:
            detections.extend(detect(session))
            stored = {key: value for key, value in session.items() if key != "events"}
            stored["trapsig"] = {"schema_version": SCHEMA_VERSION}
            await self.store.save("trapsig-sessions", session["session_id"], stored)
        for detection in detections:
            detection["trapsig"] = {"schema_version": SCHEMA_VERSION}
            await self.store.save(
                "trapsig-detections", detection["detection_id"], detection
            )
        self.sessions_written = len(sessions)
        self.detections_written = len(detections)
        self.last_run = datetime.now(timezone.utc).isoformat()
        self.last_error = None
        return {"sessions": len(sessions), "detections": len(detections)}

    async def run(self) -> None:
        interval = get_settings().processing_interval_seconds
        while not self._stop.is_set():
            try:
                await self.process_once()
            except Exception as exc:
                self.last_error = str(exc)
                LOGGER.exception("event processing cycle failed")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=interval)
            except TimeoutError:
                pass

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self.run())

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            await self._task

    def status(self) -> dict[str, Any]:
        return {
            "last_run": self.last_run,
            "last_error": self.last_error,
            "sessions_written": self.sessions_written,
            "detections_written": self.detections_written,
        }


processor: EventProcessor | None = None


def configure_processor(store: Any) -> EventProcessor:
    global processor
    processor = EventProcessor(store)
    return processor
