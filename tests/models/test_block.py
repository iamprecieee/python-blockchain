from collections import deque
from typing import Deque

from app.models import Block, Transaction
from tests import *


def test_block_initialization():
    """Test that a block can be created with default values."""
    block = Block()
    assert all(
        [
            block.index == 0,
            isinstance(block.transactions, Deque),
            len(block.transactions) == 0,
            block.previous_hash is None,
            block.nonce == 0,
            block.current_hash is not None,
        ]
    )


def test_block_with_custom_values():
    """Test that a block can be created with custom values."""
    transaction = Transaction(
        sender=SENDER_ADDRESS,
        recipient=RECIPIENT_ADDRESS,
        amount=5.0,
    )

    transactions = deque([transaction])
    block = Block(index=1, transactions=transactions, previous_hash="0x" + ("0" * 64))
    assert all(
        [
            block.index == 1,
            len(block.transactions) == 1,
            block.previous_hash == "0x" + ("0" * 64),
            block.current_hash is not None,
        ]
    )


def test_genesis_block_detection():
    """Test that the `is_genesis` property correctly identifies a genesis block."""
    genesis_block = Block(index=0, previous_hash=None)
    regular_block = Block(index=1, previous_hash="0x" + ("0" * 64))
    assert all([genesis_block.is_genesis, not regular_block.is_genesis])


def test_block_mining():
    """Test that mining a block produces a hash with the required difficulty."""
    block = Block(index=1, previous_hash="0x" + ("0" * 64))
    difficulty = 2
    block.mine(difficulty=difficulty)
    assert all([block.current_hash.startswith("0" * difficulty), block.is_valid()])


def test_block_validation():
    """Test that block validation correctly detects valid and invalid blocks."""
    block = Block(index=1, previous_hash="0x" + ("0" * 64))
    block.mine(difficulty=1)
    assert block.is_valid()
    original_hash = block.current_hash
    block.nonce += 1
    assert not block.is_valid()
    block.nonce -= 1
    block.current_hash = (
        original_hash.replace(original_hash[-1], "0")
        if original_hash[-1] != "0"
        else original_hash.replace(original_hash[-1], "1")
    )
    assert not block.is_valid()
    block.current_hash = original_hash
    assert block.is_valid()
    assert block.hash == "0x" + block.current_hash
