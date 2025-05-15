from app.models import *
from tests import *


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
            len(genesis_block.transactions) == 1,
        ]
    )
    genesis_transaction = genesis_block.transactions[0]
    assert all(
        [
            genesis_transaction.sender == "0",
            genesis_transaction.recipient == "0",
            genesis_transaction.amount == 0,
            genesis_transaction.message == "Genesis Block - First block onchain.",
            genesis_transaction.block is genesis_block,
        ]
    )


def test_blockchain_with_custom_difficulty():
    """Test blockchain initialization with custom difficulty."""
    custom_difficulty = 3
    blockchain = Blockchain(difficulty=custom_difficulty)
    assert blockchain.difficulty == custom_difficulty
    genesis_block = blockchain.chain[0]
    hash_without_prefix = genesis_block.current_hash
    assert hash_without_prefix.startswith("0" * custom_difficulty)


def test_add_transaction():
    """Test adding transactions to the blockchain."""
    blockchain = Blockchain(difficulty=1)
    transaction = Transaction(
        sender=SENDER_ADDRESS,
        recipient=RECIPIENT_ADDRESS,
        amount=5.0,
    )
    success = blockchain.add_transaction(transaction)
    assert all(
        [
            success,
            len(blockchain.pending_transactions) == 1,
            blockchain.pending_transactions[0] is transaction,
            transaction.nonce == 1,
            blockchain.account_nonces[SENDER_ADDRESS] == 1,
        ]
    )


def test_add_system_transaction():
    """Test adding a system transaction (from address '0')."""
    blockchain = Blockchain(difficulty=1)
    transaction = Transaction(sender="0", recipient=RECIPIENT_ADDRESS, amount=1.0)
    success = blockchain.add_transaction(transaction)
    assert all(
        [success, len(blockchain.pending_transactions) == 1, transaction.nonce == 0]
    )


def test_add_multiple_transactions():
    """Test adding multiple transactions from the same sender."""
    blockchain = Blockchain(difficulty=1)
    sender = SENDER_ADDRESS
    transaction1 = Transaction(
        sender=sender,
        recipient=RECIPIENT_ADDRESS,
        amount=5.0,
    )
    blockchain.add_transaction(transaction1)
    assert transaction1.nonce == 1
    transaction2 = Transaction(
        sender=sender,
        recipient=RECIPIENT_ADDRESS,
        amount=3.0,
    )
    blockchain.add_transaction(transaction2)
    assert all(
        [
            transaction2.nonce == 2,
            blockchain.account_nonces[sender] == 2,
            len(blockchain.pending_transactions) == 2,
        ]
    )


def teest_mine_block():
    """Test mining a new block."""
    blockchain = Blockchain()
    transaction = Transaction(
        sender=SENDER_ADDRESS,
        recipient=RECIPIENT_ADDRESS,
        amount=5.0,
    )
    blockchain.add_transaction(transaction)
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
            len(block.transactions) == 2,
            block.transactions[0] is transaction,
            block.transactions[0].status == Transaction.TransactionStatus.CONFIRMED,
            block.transactions[0].block is block,
        ]
    )
    reward_transaction = block.transactions[1]
    assert all(
        [
            reward_transaction.sender == "0",
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


def test_validate_chain():
    """Test blockchain validation."""
    blockchain = Blockchain(difficulty=1)
    assert blockchain.validate_chain()
    transaction = Transaction(
        sender=SENDER_ADDRESS,
        recipient=RECIPIENT_ADDRESS,
        amount=5.0,
    )
    blockchain.add_transaction(transaction)
    blockchain.mine_block(MINER_ADDRESS)
    assert blockchain.validate_chain()
    blockchain.chain[1].nonce += 1
    assert not blockchain.validate_chain()
    blockchain.chain[1].nonce -= 1
    assert blockchain.validate_chain()


def test_get_balance():
    """Test balance calculation for addresses."""
    blockchain = Blockchain(difficulty=1)
    sender = SENDER_ADDRESS
    recipient = RECIPIENT_ADDRESS
    miner = MINER_ADDRESS
    assert all(
        [
            blockchain.get_balance(sender) == 0,
            blockchain.get_balance(recipient) == 0,
            blockchain.get_balance(miner) == 0,
        ]
    )
    transaction = Transaction(sender=sender, recipient=recipient, amount=5.0)
    blockchain.add_transaction(transaction)
    blockchain.mine_block(miner)
    assert all(
        [
            blockchain.get_balance(sender) == -5.0,
            blockchain.get_balance(recipient) == 5.0,
            blockchain.get_balance(miner) == 1.0,
        ]
    )
    transaction2 = Transaction(sender=recipient, recipient=sender, amount=2.0)
    blockchain.add_transaction(transaction2)
    blockchain.mine_block(miner)
    assert all(
        [
            blockchain.get_balance(sender) == -5.0 + 2.0,
            blockchain.get_balance(recipient) == 5.0 - 2.0,
            blockchain.get_balance(miner) == 1.0 + 1.0,
        ]
    )
    system_balance = blockchain.get_balance("0")
    assert system_balance == 0
