import hashlib
from collections import deque
from datetime import datetime
from typing import Any, Deque

from pydantic import BaseModel, Field


class Block(BaseModel):
    index: int = Field(default=0)
    timestamp: int = Field(default_factory=lambda: int(datetime.now().timestamp()))
    transaction_hashes: Deque[str] = Field(default_factory=lambda: deque([]))
    previous_hash: str | None = Field(default=None)
    nonce: int = Field(default=0)
    block_hash: str | None = Field(default=None)

    def model_post_init(self, context: Any) -> None:
        if self.block_hash is None:
            self.block_hash = self._calculate_block_hash()
        return super().model_post_init(context)

    def _calculate_block_hash(self) -> str:
        """Calculate the hash value for a block using SHA-256."""
        excluded_fields = {"block_hash"}
        block_data_str = self.model_dump_json(exclude=excluded_fields)
        return hashlib.sha256(block_data_str.encode()).hexdigest()

    @property
    def hash(self) -> str | None:
        """Get the current hash value of a block with 0x prefix."""
        return "0x" + self.block_hash if self.block_hash else self.block_hash

    @property
    def is_genesis(self) -> bool:
        """Check if a block is the genesis block (first in the chain)."""
        return self.index == 0 and self.previous_hash is None

    def is_valid(self) -> bool:
        """Verify the hash value of a block."""
        return self.block_hash == self._calculate_block_hash()

    def mine(self, difficulty: int) -> None:
        """
        Find a hash value with the given difficulty (number of leading zeros).
        This implements the proof-of-work consensus mechanism.
        """
        target = "0" * difficulty
        if self.block_hash is None:
            self.block_hash = self._calculate_block_hash()
        while self.block_hash[:difficulty] != target:
            self.nonce += 1
            self.block_hash = self._calculate_block_hash()
