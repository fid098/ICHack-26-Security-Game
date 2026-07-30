from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app, store
from app.schemas import FrontendTask, TaskSchema


@pytest.fixture(autouse=True)
def isolate_environment(monkeypatch):
    """Keep every test off the network and out of the developer's real .env.

    app.main calls load_dotenv(override=True) at import time, so a populated
    .env would otherwise leak real API keys into the test run.
    """
    for name in (
        "ANTHROPIC_API_KEY",
        "ELEVENLABS_API_KEY",
        "HACKTRON_CMD",
        "HACKTRON_ARGS",
        "HACKTRON_MAX_WORKERS",
        "HACKTRON_TIMEOUT",
    ):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True)
def clear_store():
    """The store is a module-level singleton, so state leaks between tests."""
    store.sessions.clear()
    yield
    store.sessions.clear()


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def make_frontend_task():
    def _make(
        task_id: str = "task-1",
        *,
        is_vulnerable: bool = True,
        vulnerability_type: str = "XSS",
        system_name: str = "REACTOR",
        code: str = "el.innerHTML = userInput;",
        language: str = "javascript",
        vulnerability_line: int | None = 1,
    ) -> FrontendTask:
        return FrontendTask(
            id=task_id,
            systemName=system_name,
            code=code,
            language=language,
            isVulnerable=is_vulnerable,
            vulnerabilityType=vulnerability_type,
            vulnerabilityLine=vulnerability_line,
        )

    return _make


@pytest.fixture
def make_task_schema():
    def _make(
        task_id: str = "task-1",
        *,
        is_vulnerable: bool = True,
        vulnerability_type: str = "xss",
        difficulty: str = "easy",
        code: str = "el.innerHTML = userInput;",
        language: str = "javascript",
    ) -> TaskSchema:
        return TaskSchema(
            id=task_id,
            system_name="REACTOR",
            code=code,
            is_vulnerable=is_vulnerable,
            vulnerability_type=vulnerability_type,
            difficulty=difficulty,
            language=language,
        )

    return _make
