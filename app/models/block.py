from collections import deque
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class Block(BaseModel):
    """🧱 Block implementation for the blockchain 🧱"""

    index: int = Field(default=0)
    timestamp: int = Field(default_factory=lambda: int(datetime.now().timestamp()))
    transaction_hashes: deque[str] = Field(default_factory=lambda: deque([]))
    previous_hash: str | None = Field(default=None)
    nonce: int = Field(default=0)
    block_hash: str | None = Field(default=None)

    def model_post_init(self, context: Any) -> None:
        """🔄 Auto-initialize the block's hash after model creation 🔄"""
        if self.block_hash is None:
            self.block_hash = self._calculate_block_hash()

        return super().model_post_init(context)

    def _calculate_block_hash(self) -> str:
        """🔐 Calculate the block's cryptographic hash using SHA-256 🔐"""
        import hashlib

        excluded_fields = {"block_hash"}
        block_data_str = self.model_dump_json(exclude=excluded_fields)

        return hashlib.sha256(block_data_str.encode()).hexdigest()

    @property
    def hash(self) -> str | None:
        """🔍 Get the block's hash with the standard '0x' prefix 🔍"""
        return "0x" + self.block_hash if self.block_hash else self.block_hash

    @property
    def is_genesis(self) -> bool:
        """👑 Check if this is the first block in the chain (genesis block) 👑"""
        return self.index == 0 and self.previous_hash is None

    def is_valid(self) -> bool:
        """✅ Verify the block's integrity by recalculating its hash ✅"""
        return self.block_hash == self._calculate_block_hash()

    def mine(self, difficulty: int = 1) -> None:
        """⛏️ Mine the block with a nonce that produces a hash that meets difficulty requirement ⛏️"""
        self.nonce = 0
        while self.block_hash and not self.block_hash.startswith("0" * difficulty):
            self.nonce += 1
            self.block_hash = self._calculate_block_hash()
