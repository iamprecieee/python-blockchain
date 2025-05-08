import hashlib
from collections import deque
from datetime import datetime
from typing import Any, Deque

from pydantic import BaseModel, Field


class Block(BaseModel):
    index: int = Field(default=0)
    timestamp: int = Field(default_factory=lambda: int(datetime.now().timestamp()))
    transactions: Deque = Field(default_factory=lambda: deque([]))
    previous_hash: str | None = Field(default=None)
    nonce: int = Field(default=0)
    current_hash: str | None = Field(default=None, exclude=True)

    def model_post_init(self, context: Any) -> None:
        if self.current_hash is None:
            self.current_hash = self._calculate_block_hash()
        return super().model_post_init(context)

    def _calculate_block_hash(self) -> str:
        """Calculate the hash value for a mined block."""
        block_data_str = self.model_dump_json(exclude={"_hash"})
        return hashlib.sha256(block_data_str.encode()).hexdigest()

    @property
    def hash(self) -> str | None:
        """Get the current hash value of a block."""
        return "0x" + self.current_hash if self.current_hash else self.current_hash

    @property
    def is_genesis(self) -> bool:
        """Check if a block is the genesis block (first in the chain)."""
        return self.index == 0 and self.previous_hash is None

    def is_valid(self) -> bool:
        """Verify the hash value of a block."""
        return self.current_hash == self._calculate_block_hash()

    def mine(self, difficulty: int) -> None:
        """Find a hash value with the given difficulty (number of leading zeros)."""
        target = "0" * difficulty
        if self.current_hash is None:
            self.current_hash = self._calculate_block_hash()
        while self.current_hash[:difficulty] != target:
            self.nonce += 1
            self.current_hash = self._calculate_block_hash()
