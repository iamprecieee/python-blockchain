# Python Blockchain Implementation 🚀

## Project Overview 🎯

**Table of Contents**

- [Project Overview](#project-overview)
- [Core Components](#core-components)
- [API Endpoints](#api-endpoints)
- [Technical Details](#technical-details)
- [Architecture Highlights](#architecture-highlights)
- [Code Example](#code-example)
- [Project Structure](#project-structure)
- [Setup and Installation](#setup-and-installation)
- [Development](#development)
- [Testing](#testing)
- [Contributing](#contributing)

This project implements a blockchain from scratch in Python with a focus on learning blockchain principles and advancing Python backend development skills. The implementation includes the core blockchain concepts with a FastAPI interface for interaction.

## Core Components 🧩

- `Block`: Fundamental unit of the blockchain with proof-of-work mining capability ⛏️
    - Uses `pydantic` model for robust validation ✅
    - Implements `SHA-256` cryptographic hashing 🔐
    - Supports configurable mining difficulty and block validation ⚙️
    - Includes automatic hash calculation and nonce management 🔄

- `Transaction`: Represents value transfers with cryptographic validation 💸
    - Implements status tracking (`PENDING`, `CONFIRMED`, `FAILED`) 📊
    - Enforces address validation (`0x` format) 🎯
    - Provides unique transaction IDs with `SHA-256` hashing 🔑
    - Supports optional transaction messages 💬
    - Links to containing block once mined ⛓️
    - Includes nonce management for replay attack prevention 🛡️
    - Supports transaction status updates during lifecycle 🔄

- `Blockchain`: Manages the chain of blocks and transaction processing ⛓️
    - Maintains a dynamic transaction pool 📊
    - Validates transactions and blocks ✅
    - Tracks account nonces to prevent replay attacks 🛡️
    - Handles mining operations with automatic rewards ⛏️
    - Ensures chain integrity with multi-level validation 🔒
    - Provides balance calculation for blockchain addresses 💰

## API Endpoints 🌐

The blockchain exposes a RESTful API with the following endpoints:

### Block Operations 🧱

- `GET /blocks`: Retrieve the entire blockchain 📚
- `GET /blocks/{index}`: Get a specific block by index 🔍
- `POST /blocks/mine`: Mine a new block with pending transactions ⛏️

### Transaction Operations 💸

- `GET /transactions`: Get all pending transactions 📋
- `POST /transactions`: Create a new transaction ➕
- `GET /transactions/balance/{address}`: Get the balance for an address 💰

## Technical Details 🔧

- Built with Python `3.13+` 🐍
- Uses `FastAPI` for RESTful interface 🚀
- Implements proof-of-work consensus mechanism ⛏️
- Employs `SHA-256` for cryptographic security 🔐
- Standardized API response format 📋
- Global exception handling for robust error responses 🛡️
- Comprehensive test suite with `pytest` ✅

## Architecture Highlights 🏗️

- **Model Integration**: `Block` and `Transaction` models are integrated using forward references and model rebuilding 🔄
- **Circular Dependency Resolution**: Uses Python's `TYPE_CHECKING` alongside Pydantic's `model_rebuild()` to avoid runtime circular imports 🔄
- **Deep Copy Transactions**: Ensures data integrity with proper transaction copying during mining 🔒
- **Transaction Lifecycle**: Transactions reference their containing block once mined ⛓️
- **Chain Validation**: Validates both individual blocks and relationships between blocks ✅
- **API Response Pattern**: Consistent response format with status, message, and data fields 📋
- **Service Layer**: Uses singleton pattern for blockchain instance 🏢
- **Exception Handling**: Global exception handlers for standardized error responses 🛡️
- **Test Coverage**: Extensive test suite ensures code quality and correctness ✅

## Code Example 💻

```python
# Create a new transaction
transaction = Transaction(
    sender="0x8a35acfbc15ff81a39ae7d344fd709f28e8600b4",
    recipient="0x71c7656ec7ab88b098defb751B7401B5f6d8976f",
    amount=5.0,
    message="Payment for services"
)

# Create a blockchain with custom mining difficulty
blockchain = Blockchain(difficulty=2)

# Create necessary wallets
sender_wallet = Wallet(password="test_password")
recipient_wallet = Wallet(password="test_password2")
miner_wallet = Wallet(password="test_password3")

# Create and sign new transaction, then add it to the chain
transaction = Transaction(
    sender=sender_wallet.address,
    recipient=recipient_wallet.address,
    amount=5.0
)
transaction.set_nonce_hashed(blockchain=blockchain, wallet=sender_wallet)
transaction.sign(wallet=sender_wallet, password="test_password")
transaction.add_to_blockchain(blockchain=blockchain, wallet=sender_wallet)

# Mine a new block with pending transactions
# This automatically adds the miner reward transaction, links transactions to the block,
# and updates transaction statuses to "confirmed"
blockchain.mine_block(miner_address=sender_wallet.address)

# Verify entire blockchain integrity
assert blockchain.validate_chain()
```

## Project Structure 📁

```shell
python-blockchain/
│
├── app/  
│   ├── __init__.py            
│   ├── models/   
│   │   ├── __init__.py     
│   │   ├── block.py       
│   │   ├── blockchain.py 
│   │   └── signature.py    
│   │   └── transaction.py  
│   │   └── wallet.py  
│   ├── routers/    
│   │   ├── __init__.py
│   │   ├── blocks.py
│   │   └── transactions.py  
│   ├── schemas/    
│   │   ├── __init__.py
│   │   ├── block.py
│   │   └── transaction.py
│   ├── services/ 
│   │   ├── __init__.py
│   │   └── blockchain_service.py
│   ├── utils/ 
│   │   ├── __init__.py
│   │   ├── exceptions.py
│   │   └── responses.py
│   │   └── validators.py  
│   └── main.py   
│
├── tests/     
│   ├── __init__.py
│   ├── conftest.py        # Test fixtures and utilities
│   ├── models/ 
│   │   ├── __init__.py           # Core model unit tests
│   │   ├── test_block.py
│   │   └── test_blockchain.py
│   │   ├── test_transaction.py
│   │   └── test_wallet.py
│   └── api/ 
│       ├── __init__.py              # API endpoint tests
│       ├── test_block.py
│       ├── test_transaction.py
│       └── test_exception_handling.py
│ 
├── .gitignore      
├── .python-version        
├── pyproject.toml     
├── README.md   
└── uv.lock              
```

## Setup and Installation ⚙️

### Prerequisites

Ensure you have the following installed:

- **uv**:
    - <details><summary>macOS / linux</summary>

        ```shell
        curl -LsSf https://astral.sh/uv/install.sh | sh
        ```
        </details>
    - <details><summary>windows</summary>

        ```shell
        powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
        ```
        </details>
    
- **Python 3.13**:

    ```shell
    uv python install 3.13
    ```

### Steps

- Clone this repository:

    ```shell
    git clone https://github.com/iamprecieee/python-blockchain.git
    cd python-blockchain
    ```
- Set up virtual environment:
    - <details><summary>macOS / linux</summary>

        ```shell
        uv venv --python 3.13
        source .venv/bin/activate
        ```
        </details>
    - <details><summary>windows</summary>

        ```shell
        uv venv --python 3.13
        .venv\Scripts\Activate
        ```
        </details>

- Install dependencies:

    ```shell
    uv sync --active
    ```

## Development 🛠️

This project uses the following tools for development:

- `black` for code formatting ✨
- `isort` for import sorting 📦
- `mypy` for static type checking ✅
- `ruff` for linting 🔍

## Testing 🧪

This project includes a comprehensive test suite built with `pytest`:

- **Unit Tests**: Tests for `Block`, `Transaction`, and `Blockchain` classes ✅
- **API Tests**: Tests for all API endpoints and error handling 🌐
- **Test Fixtures**: Centralized test fixtures and utilities in `conftest.py` 🧩

To run the tests:

```shell
# Run all tests
pytest

# Run with coverage report
pytest --cov=app

# Run specific test modules
pytest tests/models/test_block.py
```

## Contributing 🤝

Contributions are welcome! Please feel free to submit a Pull Request.