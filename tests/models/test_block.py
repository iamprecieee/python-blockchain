from app.models import Block


def test_block_initialization():
    """Test that a block can be created with default values."""
    from collections import deque

    block = Block()
    assert all(
        [
            block.index == 0,
            isinstance(block.transaction_hashes, deque),
            len(block.transaction_hashes) == 0,
            block.previous_hash is None,
            block.nonce == 0,
            block.block_hash is not None,
        ]
    )


def test_block_with_custom_values():
    """Test that a block can be created with custom values."""
    transaction_hashes = ["0x123abc", "0x456def"]
    block = Block(index=1, transaction_hashes=transaction_hashes, previous_hash="0x" + ("0" * 64))
    assert all(
        [
            block.index == 1,
            len(block.transaction_hashes) == 2,
            block.previous_hash == "0x" + ("0" * 64),
            block.block_hash is not None,
        ]
    )


def test_genesis_block_detection():
    """Test that the `is_genesis` property correctly identifies a genesis block."""
    genesis_block = Block(index=0, previous_hash=None)
    regular_block = Block(index=1, previous_hash="0x" + ("0" * 64))

    assert all([genesis_block.is_genesis, not regular_block.is_genesis])


def test_block_validation():
    """Test that block validation correctly detects valid and invalid blocks."""
    block = Block(index=1, previous_hash="0x" + ("0" * 64))
    # block.mine(difficulty=1)
    assert block.is_valid()

    original_hash = block.block_hash
    block.nonce += 1

    assert not block.is_valid()

    block.nonce -= 1
    block.block_hash = (
        original_hash.replace(original_hash[-1], "0")
        if original_hash[-1] != "0"
        else original_hash.replace(original_hash[-1], "1")
    )

    assert not block.is_valid()

    block.block_hash = original_hash

    assert block.is_valid()
    assert block.hash == "0x" + block.block_hash


def test_block_mining():
    """Test that mining a block produces a hash with the required difficulty."""
    block = Block(index=1, previous_hash="0x" + ("0" * 64))
    difficulty = 2
    block.mine(difficulty=difficulty)

    assert all([block.block_hash.startswith("0" * difficulty), block.is_valid()])
