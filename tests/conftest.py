"""Shared fixtures."""

import pytest

from broker.broker import PacketBroker


@pytest.fixture
def broker():
    return PacketBroker()
