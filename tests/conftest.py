# tests/conftest.py
import random
import string
from datetime import datetime, timezone, timedelta
import pytest
import asyncio

from security_reasoner import SecurityReasonerEngine, Config, SecurityEvent, ThreatLevel


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
def engine(event_loop):
    """A single engine instance for the whole test run (fast, deterministic)."""
    cfg = Config()
    # If you want a fresh calibrator each run you can point to a temp dir:
    # cfg = Config.from_dict({"CALIBRATION_VERSION": "test"})
    eng = SecurityReasonerEngine(cfg)
    # start the async workers once
    event_loop.run_until_complete(eng.start())
    yield eng
    # shut down cleanly
    event_loop.run_until_complete(eng.stop())


def random_string(min_len=5, max_len=20):
    length = random.randint(min_len, max_len)
    return "".join(random.choices(string.ascii_letters + " ", k=length)).strip()


@pytest.fixture
def make_event():
    """Factory fixture that returns a function to create event dictionaries."""
    def _make_event(
        *,
        event_id: str = None,
        event_type: str = "motion",
        hour: int = None,
        location: str = "main entrance",
        description: str = None,
        confidence: float = 1.0,
        metadata: dict = None,
    ) -> dict:
        """Factory that returns a plain dict ready for `engine.process_event`."""
        now = datetime.now(timezone.utc)
        if hour is not None:
            # clamp to 0-23 and keep the same day
            now = now.replace(hour=hour % 24)
        return {
            "event_id": event_id or f"ev-{random.randint(0, 1_000_000)}",
            "event_type": event_type,
            "timestamp": now.isoformat(),
            "source": random_string(),
            "location": location,
            "description": description or random_string(),
            "metadata": metadata or {},
            "confidence": confidence,
        }
    return _make_event