import os

import pytest

# from app.main import app
# from app.services.blockchain_service import get_blockchain
from app.models.wallet import Wallet
from tests import TEST_PASSWORD

# from fastapi.testclient import TestClient


@pytest.fixture
def wallet():
    """Create a test wallet with a fixed password."""
    return Wallet(password=TEST_PASSWORD)


# @pytest.fixture
# def client():
#     """Return a TestClient for the FastAPI app."""
#     return TestClient(app)


# @pytest.fixture(autouse=True)
# def reset_blockchain():
#     """Reset the blockchain to its initial state before each test."""
#     get_blockchain.cache_clear()
#     yield
