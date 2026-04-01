"""Integration test fixtures — require a live GVM instance.

Run with:
    GVM_INTEGRATION=1 GVM_HOST=127.0.0.1 GVM_PORT=9393 GVM_PASSWORD=admin \
        pytest tests/integration/ -v
"""

from __future__ import annotations

import os

import pytest

from openvas_mcp.gvm_client import gmp_session


@pytest.fixture(autouse=True, scope="session")
def require_gvm_integration():
    """Skip all integration tests unless GVM_INTEGRATION=1 is set."""
    if os.environ.get("GVM_INTEGRATION") != "1":
        pytest.skip("Set GVM_INTEGRATION=1 to run integration tests")


@pytest.fixture
def gvm(require_gvm_integration):
    """Yield an authenticated GMP session for direct GVM calls (e.g. cleanup)."""
    with gmp_session() as g:
        yield g
