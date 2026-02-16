"""Pytest configuration and fixtures."""

import pytest


@pytest.fixture
def event_loop_policy():
    """Use the default event loop policy."""
    import asyncio

    return asyncio.DefaultEventLoopPolicy()
