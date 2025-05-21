from app.models import Blockchain, Transaction
from tests import MINER_ADDRESS, RECIPIENT_ADDRESS, TEST_PASSWORD


def test_blockchain_initialization():
    """Test that blockchain initializes correctly with a genesis block."""
    blockchain = Blockchain()
    assert all([blockchain.chain_length == 1, len(blockchain.chain) == 1])

    genesis_block = blockchain.chain[0]
    assert all(
        [
            genesis_block.index == 0,
            genesis_block.previous_hash is None,
            genesis_block.is_genesis,
            len(genesis_block.transaction_hashes) == 1,
        ]
    )

    genesis_transaction = blockchain.transactions_by_hash[genesis_block.transaction_hashes[0]]
    assert all(
        [
            genesis_transaction.sender == "0x",
            genesis_transaction.recipient == "0x",
            genesis_transaction.amount == 0,
            genesis_transaction.message == "Genesis Block - First block onchain.",
            genesis_transaction.block_index is genesis_block.index,
        ]
    )


def test_blockchain_with_custom_difficulty():
    """Test blockchain initialization with custom difficulty."""
    custom_difficulty = 3
    blockchain = Blockchain(difficulty=custom_difficulty)

    assert blockchain.difficulty == custom_difficulty

    genesis_block = blockchain.chain[0]
    hash_without_prefix = genesis_block.block_hash

    assert hash_without_prefix.startswith("0" * custom_difficulty)


def test_mine_block(wallet):
    """Test mining a new block."""
    blockchain = Blockchain()
    transaction = Transaction(
        sender=wallet.address,
        recipient=RECIPIENT_ADDRESS,
        amount=5.0,
    )
    transaction.set_nonce_hashed(blockchain, wallet)
    transaction.sign(wallet, TEST_PASSWORD)
    transaction.add_to_blockchain(blockchain, wallet)
    miner_address = MINER_ADDRESS
    block = blockchain.mine_block(miner_address)

    assert all(
        [
            block is not None,
            blockchain.chain_length == 2,
            len(blockchain.chain) == 2,
            blockchain.chain[1] is block,
            block.index == 1,
            block.previous_hash == blockchain.chain[0].hash,
            len(block.transaction_hashes) == 2,
            block.transaction_hashes[0] is transaction.transaction_hash,
            transaction.status == Transaction.TransactionStatus.CONFIRMED,
            transaction.block_index is block.index,
        ]
    )

    reward_transaction = blockchain.transactions_by_hash[block.transaction_hashes[1]]
    assert all(
        [
            reward_transaction.sender == "0x",
            reward_transaction.recipient == miner_address,
            reward_transaction.amount == 1.0,
            reward_transaction.status == Transaction.TransactionStatus.CONFIRMED,
            len(blockchain.pending_transactions) == 0,
        ]
    )


def test_mine_empty_block():
    """Test mining a block with no transactions."""
    blockchain = Blockchain(difficulty=1)
    block = blockchain.mine_block(MINER_ADDRESS)

    assert block is None
    assert blockchain.chain_length == 1


def test_validate_chain(wallet):
    """Test blockchain validation."""
    blockchain = Blockchain(difficulty=1)
    assert blockchain.validate_chain()

    transaction = Transaction(
        sender=wallet.address,
        recipient=RECIPIENT_ADDRESS,
        amount=5.0,
    )
    transaction.set_nonce_hashed(blockchain, wallet)
    transaction.sign(wallet, TEST_PASSWORD)
    transaction.add_to_blockchain(blockchain, wallet)
    blockchain.mine_block(MINER_ADDRESS)

    assert blockchain.validate_chain()

    blockchain.chain[1].nonce += 1
    assert not blockchain.validate_chain()

    blockchain.chain[1].nonce -= 1
    assert blockchain.validate_chain()
