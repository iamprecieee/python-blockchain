## Project Overview

This project implements a blockchain from scratch in Python with a focus on learning blockchain principles and advancing Python backend development skills. The implementation includes the core blockchain concepts with a FastAPI interface for interaction.

## Core Components

## Technical Details

-  Built with Python 3.13+
-  Uses FastAPI for RESTful interface

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
```shell
# macos/linux.
curl -LsSf https://astral.sh/uv/install.sh | sh
```
```shell
# windows.
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```
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
```shell
uv venv --python 3.13
source .venv/bin/activate # macos/linux.
.venv\Scripts\Activate # windows.
```
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