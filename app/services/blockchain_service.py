from functools import lru_cache

from app.models import *
from app.models.blockchain import Blockchain


@lru_cache(maxsize=1)
def get_blockchain() -> Blockchain:
    """Return singleton blockchain instance"""
    return Blockchain(difficulty=2)
