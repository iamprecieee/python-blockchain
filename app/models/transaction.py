from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Optional

from pydantic import BaseModel, Field, field_validator

if TYPE_CHECKING:
    from app.models import Blockchain, TransactionSignature, Wallet


class Transaction(BaseModel):
    """💸 Transaction implementation for blockchain value transfer 💸"""

    class TransactionStatus(StrEnum):
        """📊 Possible states of a transaction in its lifecycle 📊"""

        PENDING = "pending"
        CONFIRMED = "confirmed"
        FAILED = "failed"

    nonce: int = Field(default=0, ge=0)
    sender: str = Field(default="")
    recipient: str = Field(default="")
    amount: float = Field(default=0, ge=0.0)
    status: str = Field(default=TransactionStatus.PENDING)
    timestamp: int = Field(default_factory=lambda: int(datetime.now().timestamp()))
    block_index: int | None = Field(default=None, exclude=True)
    message: str | None = Field(default=None, max_length=500)
    transaction_hash: str = Field(default="")
    signature_data: Optional["TransactionSignature"] = Field(default=None, exclude=True)

    def model_post_init(self, context: Any) -> None:
        """🔄 Initialize the transaction's hash after model creation 🔄"""
        if self.transaction_hash == "":
            self.transaction_hash = self._calculate_transaction_hash()

        return super().model_post_init(context)

    def _calculate_transaction_hash(self) -> str:
        """🔐 Calculate the transaction's cryptographic hash using SHA-256 🔐"""
        import hashlib

        excluded_fields = {"transaction_hash", "block_index", "status"}
        block_data_str = self.model_dump_json(exclude=excluded_fields)

        return hashlib.sha256(block_data_str.encode()).hexdigest()

    @property
    def hash(self) -> str | None:
        """🔍 Get the transaction's hash with the standard '0x' prefix 🔍"""
        return "0x" + self.transaction_hash if self.transaction_hash else self.transaction_hash

    @field_validator("sender", "recipient")
    @classmethod
    def validate_address(cls, address: str) -> str:
        """📏 Validate that an address follows the blockchain's format 📏"""
        if address == "0x":
            return address

        if not address.startswith("0x"):
            raise ValueError("Address must start with '0x' or be a systeem address: '0'.")

        if len(address) != 42:
            raise ValueError("Address must be 42 characters in length (0x + 40 hex chars).")

        try:
            int(address[2:], 16)
        except ValueError as e:
            raise ValueError(f"Failed to convert address string to integer: {str(e)}") from e

        return address

    def update_status(self, status: str) -> None:
        """🔄 Update the transaction's status in its lifecycle 🔄"""
        if status in self.TransactionStatus.__members__.values():
            self.status = self.TransactionStatus(status)

    def set_nonce_hashed(self, blockchain: "Blockchain", wallet: "Wallet") -> None:
        """🔢 Set the next valid nonce and recalculate the transaction hash 🔢"""
        expected_nonce = blockchain.account_nonces.get(wallet.address, 0) + 1
        self.nonce = expected_nonce
        self.transaction_hash = self._calculate_transaction_hash()

    @property
    def transaction_data(self) -> dict:
        """✍️ Get the data that will be cryptographically signed ✍️"""
        excluded_fields = {"signature_data"}
        data = self.model_dump(exclude=excluded_fields)
        data["status"], data["transaction_hash"] = str(self.status), self.hash

        return data

    def sign(self, wallet: "Wallet", password: str) -> bool:
        """✍️ Sign the transaction with the provided wallet ✍️"""
        from app.models import TransactionSignature

        if self.sender == "0x":
            return True

        if self.sender.lower() != wallet.address.lower():
            raise ValueError("Cannot sign transaction for other wallets")

        if not self.signature_data:
            self.signature_data = TransactionSignature()

        return self.signature_data.sign(self.transaction_data, wallet, password)

    def verify_signature(self) -> bool:
        """✅ Verify the transaction's cryptographic signature ✅"""
        if self.sender == "0x":
            return True

        if not self.signature_data:
            return False

        return self.signature_data.verify(self.transaction_data)

    def add_to_blockchain(
        self, blockchain: "Blockchain", wallet: Optional["Wallet"] = None
    ) -> bool:
        """📥 Add the transaction to the blockchain's transaction pool 📥"""
        from app.utils.validators import TransactionValidator

        if not TransactionValidator.validate_basic_fields(self):
            return False

        if self.sender == "0x":
            self.nonce = 0
            if not TransactionValidator.validate_transaction(self, blockchain.account_nonces):
                return False

            blockchain.transactions_by_hash[self.transaction_hash] = self
            blockchain.pending_transactions.append(self)

            return True

        if not wallet:
            return False

        expected_nonce = blockchain.account_nonces.get(self.sender, 0) + 1
        if self.nonce == 0:
            self.nonce = expected_nonce
        if self.nonce == expected_nonce:
            if not TransactionValidator.validate_transaction(self, blockchain.account_nonces):
                return False

            blockchain.transactions_by_hash[self.transaction_hash] = self
            blockchain.pending_transactions.append(self)
            blockchain.account_nonces[self.sender] = self.nonce

            return True

        elif self.nonce > expected_nonce:
            if not TransactionValidator.validate_transaction(
                self, blockchain.account_nonces, check_nonce=False
            ):
                return False

            blockchain.transactions_by_hash[self.transaction_hash] = self
            blockchain.future_transactions.setdefault(self.sender, {})[self.nonce] = self

            return True

        return False
