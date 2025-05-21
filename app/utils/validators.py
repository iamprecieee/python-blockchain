from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.models import Transaction


class TransactionValidator:
    """🕵️‍♂️ Validation utilities for blockchain transactions 🕵️‍♂️"""

    @staticmethod
    def validate_basic_fields(transaction: "Transaction") -> bool:
        """✅ Validate basic transaction fields such as amount, sender, recipient, and status ✅"""
        if any(
            [
                transaction.amount <= 0,
                transaction.sender == "",
                transaction.recipient == "",
                transaction.status != transaction.TransactionStatus.PENDING,
            ]
        ):
            return False

        return True

    @staticmethod
    def validate_nonce(transaction: "Transaction", account_nonces: dict[str, int]) -> bool:
        """✅ Validate that the transaction's nonce is correct for the sender ✅"""
        if transaction.sender == "0x":
            return transaction.nonce == 0

        expected_nonce = account_nonces.get(transaction.sender, 0) + 1
        return transaction.nonce == expected_nonce

    @staticmethod
    def validate_signature(transaction: "Transaction") -> bool:
        """✅ Validate the cryptographic signature of the transaction ✅"""
        if transaction.sender == "0x":
            return True

        return transaction.verify_signature()

    @staticmethod
    def validate_transaction(
        transaction: "Transaction", account_nonces: dict[str, int], check_nonce: bool = True
    ) -> bool:
        """✅ Perform complete transaction validation, including fields, nonce, and signature ✅"""
        if not TransactionValidator.validate_basic_fields(transaction):
            return False

        if check_nonce and not TransactionValidator.validate_nonce(transaction, account_nonces):
            return False

        if transaction.sender != "0x" and not TransactionValidator.validate_signature(transaction):
            return False

        return True
