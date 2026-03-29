"""Shared pytest fixtures."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def mock_gmp():
    """A MagicMock pre-configured as a Gmp session object."""
    return MagicMock()


@pytest.fixture
def gmp_session_mock(mock_gmp):
    """Patch gmp_session in the server module to yield mock_gmp."""

    @contextmanager
    def _fake_session():
        yield mock_gmp

    with patch("openvas_mcp.server.gmp_session", side_effect=_fake_session):
        yield mock_gmp


def xml_fromstring(s: str) -> ET.Element:
    """Parse an XML string into an Element — test helper."""
    return ET.fromstring(s)


# Integration tests (require a live GVM instance) are gated behind:
#   GVM_INTEGRATION=1 pytest tests/integration/
# Not yet implemented — planned alongside Docker distribution.
