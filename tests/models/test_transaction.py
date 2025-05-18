import copy

import pytest

from app.models import Blockchain, Transaction, Wallet
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
            transaction.block_index is None,
            transaction.message is None,
            transaction.transaction_hash is not None,
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
        sender="0x",
        recipient=RECIPIENT_ADDRESS,
        amount=1.0,
        message="Mining reward",
    )
    assert all(
        [
            transaction.sender == "0x",
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
    transaction2 = Transaction(sender="0x", recipient=RECIPIENT_ADDRESS)
    assert transaction2.sender == "0x"
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


def test_transaction_hash_generation(wallet):
    """Test that transaction hashes are generated correctly."""
    blockchain = Blockchain(difficulty=1)
    transaction = Transaction(
        sender=wallet.address,
        recipient=RECIPIENT_ADDRESS,
        amount=5.0,
    )
    initial_hash = transaction.transaction_hash
    assert initial_hash is not None
    original_nonce = transaction.nonce
    transaction.nonce = original_nonce + 1
    transaction.set_nonce_hashed(blockchain, wallet)
    new_hash = transaction.transaction_hash
    assert new_hash != initial_hash
    wallet2 = Wallet(password=TEST_PASSWORD, private_key_hex=None, encrypted_key=None)
    transaction2 = Transaction(
        sender=wallet2.address,
        recipient=RECIPIENT_ADDRESS,
        amount=5.0,
    )
    transaction2.set_nonce_hashed(blockchain, wallet)
    assert transaction2.transaction_hash != initial_hash


def test_transaction_block_association():
    """Test associating a transaction with a block."""
    transaction = Transaction(
        sender=SENDER_ADDRESS,
        recipient=RECIPIENT_ADDRESS,
        amount=5.0,
    )
    transaction.block_index = 1
    assert all(
        [
            transaction.block_index == 1,
            transaction.status == Transaction.TransactionStatus.PENDING,
        ]
    )
    transaction.update_status("confirmed")
    assert transaction.status == Transaction.TransactionStatus.CONFIRMED


def test_transaction_signature(wallet):
    """Test transaction signature using composition with TransactionSignature."""
    transaction = Transaction(
        sender=wallet.address,
        recipient=RECIPIENT_ADDRESS,
        amount=5.0,
    )
    with pytest.raises(ValueError):
        transaction_copy = copy.deepcopy(transaction)
        transaction_copy.sender = SENDER_ADDRESS
        transaction_copy.sign(wallet, TEST_PASSWORD)
    transaction.sign(wallet, TEST_PASSWORD)
    assert all(
        [
            transaction.signature_data is not None,
            transaction.signature_data.signature is not None,
            transaction.signature_data.public_key is not None,
        ]
    )
    assert transaction.verify_signature()
    transaction.amount = 10.0
    assert not transaction.verify_signature()


def test_add_transaction_to_blockchain(wallet):
    """Test adding transactions to the blockchain."""
    blockchain = Blockchain(difficulty=1)
    transaction = Transaction(sender=wallet.address, recipient=RECIPIENT_ADDRESS, amount=5.0)
    transaction.set_nonce_hashed(blockchain, wallet)
    transaction.sign(wallet, TEST_PASSWORD)
    success = transaction.add_to_blockchain(blockchain, wallet)
    assert all(
        [
            success,
            len(blockchain.pending_transactions) == 1,
            blockchain.pending_transactions[0] is transaction,
            transaction.nonce == 1,
            blockchain.account_nonces[wallet.address] == 1,
        ]
    )


def test_add_system_transaction():
    """Test adding a system transaction (from address '0')."""
    blockchain = Blockchain(difficulty=1)
    transaction = Transaction(sender="0x", recipient=RECIPIENT_ADDRESS, amount=1.0)
    success = transaction.add_to_blockchain(blockchain)
    assert all([success, len(blockchain.pending_transactions) == 1, transaction.nonce == 0])


def test_add_multiple_transactions(wallet):
    """Test adding multiple transactions from the same sender."""
    blockchain = Blockchain(difficulty=1)
    transaction1 = Transaction(sender=wallet.address, recipient=RECIPIENT_ADDRESS, amount=5.0)
    transaction1.set_nonce_hashed(blockchain, wallet)
    transaction1.sign(wallet, TEST_PASSWORD)
    transaction1.add_to_blockchain(blockchain, wallet)
    assert transaction1.nonce == 1
    transaction2 = Transaction(sender=wallet.address, recipient=RECIPIENT_ADDRESS, amount=5.0)
    transaction2.set_nonce_hashed(blockchain, wallet)
    transaction2.sign(wallet, TEST_PASSWORD)
    transaction2.add_to_blockchain(blockchain, wallet)
    assert all(
        [
            transaction2.nonce == 2,
            blockchain.account_nonces[wallet.address] == 2,
            len(blockchain.pending_transactions) == 2,
        ]
    )
