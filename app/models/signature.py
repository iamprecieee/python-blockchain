from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from app.models import Wallet


class TransactionSignature(BaseModel):
    """✍️ Cryptographic signature implementation for a blockchain transaction ✍️"""

    signature: str | None = Field(default=None)
    public_key: str | None = Field(default=None)

    def sign(self, transaction_data: dict, wallet: "Wallet", password: str) -> bool:
        """🔐 Sign transaction data with the provided wallet's private key 🔐"""
        try:
            signature_bytes = wallet.sign_transaction(transaction_data, password)
            self.signature = "0x" + signature_bytes.hex()
            self.public_key = wallet.get_public_key_hex()

            return True

        except Exception:
            return False

    def verify(self, transaction_data: dict) -> bool:
        """✅ Verify the signature against transaction data ✅"""
        from app.models import Wallet

        if not self.signature or not self.public_key:
            return False

        signature = self.signature[2:] if self.signature.startswith("0x") else self.signature
        public_key = self.public_key[2:] if self.public_key.startswith("0x") else self.public_key

        try:
            return Wallet.verify_signature(
                transaction_data, bytes.fromhex(signature), bytes.fromhex(public_key)
            )

        except Exception:
            return False
