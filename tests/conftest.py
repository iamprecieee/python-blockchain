import pytest

from app.models.wallet import Wallet
from tests import TEST_PASSWORD


@pytest.fixture
def wallet():
    """Create a test wallet with a fixed password."""
    return Wallet(password=TEST_PASSWORD)
