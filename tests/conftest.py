"""Shared fixtures, plus the rule that skips netns tests when there are no privileges."""

import pytest

from broker.broker import PacketBroker
from broker.netns import have_privileges


def pytest_collection_modifyitems(items):
    if have_privileges():
        return
    skip = pytest.mark.skip(reason="needs Linux, root and iproute2")
    for item in items:
        if "netns" in item.keywords:
            item.add_marker(skip)


def pytest_html_report_title(report):
    report.title = "packet-broker-qa-lab test report"


@pytest.fixture
def broker():
    return PacketBroker()
