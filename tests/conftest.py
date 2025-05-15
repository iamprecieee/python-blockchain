import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services.blockchain_service import get_blockchain


@pytest.fixture
def client():
    """Return a TestClient for the FastAPI app."""
    return TestClient(app)


@pytest.fixture(autouse=True)
def reset_blockchain():
    """Reset the blockchain to its initial state before each test."""
    get_blockchain.cache_clear()
    yield
