import copy
from collections import deque
from typing import Deque

from app.models import *


class Blockchain:
    def __init__(self, difficulty: int = 1) -> None:
        self.chain: Deque[Block] = deque([])
        self.chain_length = 0
        self.account_nonces: dict[str, int] = {}
        self.pending_transactions: Deque[Transaction] = deque([])
        self.difficulty = difficulty
        self._create_genesis_block()

    def _create_genesis_block(self) -> None:
        """Create the first block in the chain."""
        genesis_transaction = Transaction(
            sender="0",
            recipient="0",
            amount=0,
            message="Genesis Block - First block onchain.",
        )
        genesis_block = Block(
            index=0,
            transactions=deque([genesis_transaction]),
            previous_hash="0x" + ("0" * 64),
        )
        genesis_transaction.block = genesis_block
        genesis_block.mine(difficulty=self.difficulty)
        self.chain.append(genesis_block)
        self.chain_length += 1

    def _validate_transaction(self, transaction: dict) -> bool:
        """Validate that the transaction has the required fields and valid values."""
        if not all(
            [field in transaction for field in {"sender", "recipient", "amount"}]
        ):
            return False
        if (
            not isinstance(transaction["amount"], (int, float))
            or transaction["amount"] <= 0.0
        ):
            return False
        if transaction["status"] != Transaction.TransactionStatus.PENDING:
            return False
        if transaction["sender"] == "0":
            if transaction["nonce"] != 0:
                return False
        else:
            expected_nonce = self.account_nonces.get(transaction["sender"], 0) + 1
            if transaction["nonce"] != expected_nonce:
                return False
        return True

    def _collect_pending_transactions(self) -> Deque:
        """Clear and return a copy of pending transactions."""
        pending_copy = copy.deepcopy(self.pending_transactions)
        self.pending_transactions.clear()
        return pending_copy

    def _validate_block(
        self, block: Block, previous_block: Block | None = None
    ) -> bool:
        """Validate a block's internal consistency and link to previous block"""
        if not block.is_valid():
            return False
        if previous_block:
            if block.previous_hash != previous_block.hash or block.index != (
                previous_block.index + 1
            ):
                return False
        return True

    def _add_block(self, block: Block) -> Block | None:
        """Add a new block to the chain."""
        if not self._validate_block(block):
            return None
        self.chain.append(block)
        self.chain_length += 1
        return block

    def add_transaction(self, transaction: Transaction) -> bool:
        """Add a transaction to the pending pool if valid."""
        if transaction.sender == "0":
            transaction.nonce = 0
        else:
            current_transaction_nonce = self.account_nonces.get(transaction.sender, 0)
            transaction.nonce = current_transaction_nonce + 1
        is_valid_transaction = self._validate_transaction(transaction.model_dump())
        if is_valid_transaction:
            transaction.hash_nonce()
            self.pending_transactions.append(transaction)
            if transaction.sender != "0":
                self.account_nonces[transaction.sender] = transaction.nonce
        return is_valid_transaction

    def mine_block(self, miner_address: str) -> Block | None:
        """Mine a new block with pending transactions."""
        if not self.pending_transactions:
            return None
        reward_transaction = Transaction(
            sender="0", recipient=miner_address, amount=1.0
        )
        self.pending_transactions.append(reward_transaction)
        new_block = Block(
            index=self.chain_length,
            transactions=self._collect_pending_transactions(),
            previous_hash=self.chain[-1].hash,
        )
        for transaction in new_block.transactions:
            transaction.block = new_block
            transaction.update_status("confirmed")
        new_block.mine(difficulty=self.difficulty)
        return self._add_block(new_block)

    def validate_chain(self) -> bool:
        """Validate the entire blockchain's integrity."""
        if self.chain_length < 2:
            return True
        for i in range(1, self.chain_length):
            current_block, previous_block = self.chain[i], self.chain[i - 1]
            if not self._validate_block(current_block, previous_block=previous_block):
                return False
        return True

    def get_balance(self, address: str) -> float:
        """Calculate the current balance for an address by analyzing the blockchain."""
        balance = 0.0
        for block in self.chain:
            for transaction in block.transactions:
                if transaction.recipient == address:
                    balance += transaction.amount
                if transaction.sender == address and transaction.sender != "0":
                    balance -= transaction.amount
        return balance
