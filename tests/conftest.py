"""Pytest fixtures for spinning up the local vulnerable EdTech multi-service lab."""
from __future__ import annotations

from typing import Generator
import pytest

from lab.mock_edtech_stack import start_background_lab_server


@pytest.fixture(scope="session")
def lab_base_url() -> Generator[str, None, None]:
    """Starts the vulnerable EdTech lab server on an ephemeral localhost port for the test session."""
    server, base_url = start_background_lab_server(host="127.0.0.1", port=0)
    try:
        yield base_url
    finally:
        server.shutdown()
        server.server_close()
