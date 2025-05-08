import hashlib
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class Transaction(BaseModel):
    class TransactionStatus(StrEnum):
        PENDING = "pending"
        CONFIRMED = "confirmed"
        FAILED = "failed"

    nonce: int = Field(default=0, ge=0)
    sender: str = Field(default="")
    recipient: str = Field(default="")
    amount: float = Field(default=0, ge=0.0)
    status: str = Field(default=TransactionStatus.PENDING)
    timestamp: int = Field(default_factory=lambda: int(datetime.now().timestamp()))
    block: "Block" = Field(default=None)
    message: str | None = Field(default=None, max_length=500)
    transaction_hash: str | None = Field(default=None, exclude=True)

    def model_post_init(self, context: Any) -> None:
        if self.transaction_hash is None:
            self.transaction_hash = self._calculate_transaction_hash()
        return super().model_post_init(context)

    def _calculate_transaction_hash(self) -> str:
        """Calculate the hash value for a mined transaction."""
        block_data_str = self.model_dump_json(exclude={"transaction_hash"})
        return hashlib.sha256(block_data_str.encode()).hexdigest()

    @property
    def transaction_id(self):
        """Get the current hash value of a transaction."""
        return (
            "0x" + self.transaction_hash
            if self.transaction_hash
            else self.transaction_hash
        )

    @field_validator("sender", "recipient")
    def validate_address(cls, address: str) -> str:
        """Validate blockchain address format."""
        if not address.startswith("0x") and address != "0":
            raise ValueError(
                "Address must start with '0x' or be a systeem address: '0'."
            )
        if len(address) != 42 and address != "0":
            raise ValueError(
                "Address must be 42 characters in length (0x + 40 hex chars)."
            )
        return address

    def update_status(self, status: str) -> None:
        """Update the status of a transaction."""
        if status in self.TransactionStatus.__members__.values():
            self.status = status


from app.models.block import Block
