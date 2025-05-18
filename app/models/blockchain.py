import copy
from collections import deque
from typing import TYPE_CHECKING, Deque, Optional

if TYPE_CHECKING:
    from app.models import *


class Blockchain:
    def __init__(self, difficulty: int = 1) -> None:
        self.chain: Deque[Block] = deque([])
        self.chain_length = 0
        self.account_nonces: dict[str, int] = {}
        self.pending_transactions: Deque["Transaction"] = deque([])
        self.future_transactions: dict[str, dict[int, Transaction]] = {}
        self.transactions_by_hash: dict[str, "Transaction"] = {}
        self.difficulty = difficulty
        self._create_genesis_block()

    def _create_genesis_block(self) -> None:
        """Create the first block in the chain."""
        from app.models import Block, Transaction

        genesis_transaction = Transaction(
            sender="0x",
            recipient="0x",
            amount=0,
            message="Genesis Block - First block onchain.",
        )
        self.transactions_by_hash[genesis_transaction.transaction_hash] = genesis_transaction
        genesis_block = Block(
            index=0, transaction_hashes=deque([genesis_transaction.transaction_hash])
        )
        genesis_transaction.block_index = 0
        genesis_block.mine(difficulty=self.difficulty)
        self.chain.append(genesis_block)
        self.chain_length += 1

    def _process_future_transactions(self, sender: str) -> None:
        """Process any queued future transactions that are now valid."""
        if sender not in self.future_transactions:
            return
        expected_nonce = self.account_nonces.get(sender, 0) + 1
        while expected_nonce in self.future_transactions[sender]:
            transaction = self.future_transactions[sender].pop(expected_nonce)
            self.pending_transactions.append(transaction)
            self.account_nonces[sender] = expected_nonce
            expected_nonce += 1
        if not self.future_transactions[sender]:
            del self.future_transactions[sender]

    def mine_block(self, miner_address: str) -> Optional["Block"]:
        """Mine a new block with pending transactions."""
        from app.models import Block, Transaction

        if not self.pending_transactions:
            return None
        reward_transaction = Transaction(sender="0x", recipient=miner_address, amount=1.0)
        reward_transaction.add_to_blockchain(self)
        transaction_hashes = deque(
            [transaction.transaction_hash for transaction in self.pending_transactions]
        )
        pending_transactions_copy = copy.copy(self.pending_transactions)
        self.pending_transactions.clear()
        new_block = Block(
            index=self.chain_length,
            transaction_hashes=transaction_hashes,
            previous_hash=self.chain[-1].hash,
        )
        new_block.mine(difficulty=self.difficulty)
        if self._add_block(new_block):
            for transaction in pending_transactions_copy:
                transaction.block_index = new_block.index
                transaction.update_status("confirmed")
            return new_block
        return None

    def _add_block(self, block: "Block") -> bool:
        """Add a new block to the chain if valid."""
        if not self._validate_block(block):
            return False
        self.chain.append(block)
        self.chain_length += 1
        return True

    def _validate_block(self, block: "Block", previous_block: Optional["Block"] = None) -> bool:
        """Validate a block's internal consistency and link to previous block."""
        if not block.is_valid():
            return False
        if previous_block:
            if (
                block.previous_hash != previous_block.hash
                or block.index != previous_block.index + 1
            ):
                return False
        return True

    def validate_chain(self) -> bool:
        """Validate the entire blockchain's integrity."""
        if self.chain_length < 2:
            return True
        for i in range(1, self.chain_length):
            current_block, previous_block = self.chain[i], self.chain[i - 1]
            if not self._validate_block(current_block, previous_block=previous_block):
                return False
        return True
