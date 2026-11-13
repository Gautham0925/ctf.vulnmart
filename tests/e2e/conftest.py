import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "scripts"))
import dev_stack  # noqa: E402


@pytest.fixture(scope="session")
def stack():
    for k in ("FLAGDESK_DB_PASSWORD", "VULNMART_DB_PASSWORD"):
        if not os.environ.get(k):
            pytest.skip(f"{k} not set (needs bootstrapped DB roles)")
    procs = dev_stack.start()
    yield dev_stack
    dev_stack.stop(procs)
