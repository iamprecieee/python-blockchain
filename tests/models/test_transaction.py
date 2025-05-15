import pytest

from app.models import Block, Transaction
from tests import *


def test_transaction_initialization():
    """Test transaction initialization with default values."""
    transaction = Transaction()
    assert all(
        [
            transaction.nonce == 0,
            transaction.sender == "",
            transaction.recipient == "",
            transaction.amount == 0,
            transaction.status == Transaction.TransactionStatus.PENDING,
            transaction.block is None,
            transaction.message is None,
            transaction.transaction_id is not None,
        ]
    )


def test_transaction_with_custom_values():
    """Test transaction initialization with custom values."""

    transaction = Transaction(
        sender=SENDER_ADDRESS,
        recipient=RECIPIENT_ADDRESS,
        amount=5.0,
        message="Test transaction",
    )
    assert all(
        [
            transaction.sender == SENDER_ADDRESS,
            transaction.recipient == RECIPIENT_ADDRESS,
            transaction.amount == 5.0,
            transaction.message == "Test transaction",
            transaction.status == Transaction.TransactionStatus.PENDING,
        ]
    )


def test_system_transaction():
    """Test creating a system transaction (from address '0')."""
    transaction = Transaction(
        sender="0",
        recipient=RECIPIENT_ADDRESS,
        amount=1.0,
        message="Mining reward",
    )
    assert all(
        [
            transaction.sender == "0",
            transaction.recipient == RECIPIENT_ADDRESS,
            transaction.amount == 1.0,
            transaction.status == Transaction.TransactionStatus.PENDING,
        ]
    )


def test_address_validation():
    """Test that address validation enforces proper address format."""
    transaction1 = Transaction(
        sender=SENDER_ADDRESS,
        recipient=RECIPIENT_ADDRESS,
    )
    assert all(
        [
            transaction1.sender == SENDER_ADDRESS,
            transaction1.recipient == RECIPIENT_ADDRESS,
        ]
    )
    transaction2 = Transaction(sender="0", recipient=RECIPIENT_ADDRESS)
    assert transaction2.sender == "0"
    with pytest.raises(ValueError):
        Transaction(sender="invalid", recipient=RECIPIENT_ADDRESS)
    with pytest.raises(ValueError):
        Transaction(sender=SENDER_ADDRESS, recipient="invalid")
    with pytest.raises(ValueError):
        Transaction(
            sender="0x8a35acfbc15ff81a39ae7d344fd709f28e8600",  # Too short
            recipient=RECIPIENT_ADDRESS,
        )


def test_transaction_status_updates():
    """Test updating transaction status."""
    transaction = Transaction(
        sender=SENDER_ADDRESS,
        recipient=RECIPIENT_ADDRESS,
        amount=5.0,
    )
    assert transaction.status == Transaction.TransactionStatus.PENDING
    transaction.update_status("confirmed")
    assert transaction.status == Transaction.TransactionStatus.CONFIRMED
    transaction.update_status("failed")
    assert transaction.status == Transaction.TransactionStatus.FAILED
    transaction.update_status("invalid_status")
    assert transaction.status == Transaction.TransactionStatus.FAILED


def test_transaction_hash_generation():
    """Test that transaction hashes are generated correctly."""
    transaction = Transaction(
        sender=SENDER_ADDRESS,
        recipient=RECIPIENT_ADDRESS,
        amount=5.0,
    )
    initial_hash = transaction.transaction_id
    assert all([initial_hash is not None, initial_hash.startswith("0x")])
    original_nonce = transaction.nonce
    transaction.nonce = original_nonce + 1
    transaction.hash_nonce()
    new_hash = transaction.transaction_id
    assert new_hash != initial_hash
    transaction2 = Transaction(
        sender=SENDER_ADDRESS,
        recipient=RECIPIENT_ADDRESS,
        amount=5.0,
        nonce=original_nonce,
        timestamp=transaction.timestamp,
    )
    transaction2.hash_nonce()
    assert transaction2.transaction_id == initial_hash


def test_transaction_block_association():
    """Test associating a transaction with a block."""
    transaction = Transaction(
        sender=SENDER_ADDRESS,
        recipient=RECIPIENT_ADDRESS,
        amount=5.0,
    )
    block = Block(index=1, previous_hash="0x123")
    transaction.block = block
    assert all(
        [
            transaction.block is block,
            transaction.status == Transaction.TransactionStatus.PENDING,
        ]
    )
    transaction.update_status("confirmed")
    assert transaction.status == Transaction.TransactionStatus.CONFIRMED
