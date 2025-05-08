## Project Overview

This project implements a blockchain from scratch in Python with a focus on learning blockchain principles and advancing Python backend development skills. The implementation includes the core blockchain concepts with a FastAPI interface for interaction.

## Core Components

- `Block`: Fundamental unit of the blockchain with proof-of-work mining capability
    - Uses pydantic model for robust validation
    - Implements SHA-256 cryptographic hashing
    - Supports configurable mining difficulty and block validation 
    - Includes automatic hash calculation and nonce management

## Technical Details

- Built with Python 3.13+
- Uses FastAPI for RESTful interface
- Implements proof-of-work consensus mechanism
- Employs SHA-256 for cryptographic security

## Code Example

- The `Block` implementation includes features like:
    ```python
    # Create a new block
    block = Block(
        index=1,
        transactions=deque([{
            "sender": "0x123",
            "recipient": "0x456",
            "amount": 5.0
        }]),
        previous_hash="0x" + "0"*64
    )

    # Mine the block with difficulty level 2
    block.mine(difficulty=2)

    # Verify block validity
    is_valid = block.is_valid()
    ```

## Project Structure

```shell
python-blockchain/
│
├── app/              
│   ├── models/   
│   ├── routers/    
│   ├── services/ 
│   ├── utils/ 
│   └── main.py   
│
├── tests/     
├── .gitignore      
├── .python-version        
├── pyproject.toml     
├── README.md   
└── uv.lock              
```

## Setup and Installation

### Prerequisites

Ensure you have the following installed:

- *uv*:
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
    
- *Python 3.13*:

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

## Development

This project uses the following tools for development:

- `black` for code formatting
- `isort` for import sorting
- `mypy` for static type checking
- `ruff` for linting

## Contributing
Contributions are welcome! Please feel free to submit a Pull Request.