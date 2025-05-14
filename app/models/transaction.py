import hashlib
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator

from app.models import Block


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
    block: Block | None = Field(default=None, exclude=True)
    message: str | None = Field(default=None, max_length=500)
    transaction_id: str = "dummy"

    def model_post_init(self, context: Any) -> None:
        if self.transaction_id == "dummy":
            self.transaction_id = self._calculate_transaction_hash()
        return super().model_post_init(context)

    def _calculate_transaction_hash(self) -> str:
        """Calculate the hash value for a mined transaction."""
        block_data_str = self.model_dump_json(
            exclude={"transaction_id", "block", "status"}
        )
        return "0x" + hashlib.sha256(block_data_str.encode()).hexdigest()

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

    def hash_nonce(self):
        """Recalculate transaction hash when valid nonce value is set"""
        self.transaction_id = self._calculate_transaction_hash()
