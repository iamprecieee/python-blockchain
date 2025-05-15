from tests import *


def test_root_endpoint(client):
    """Test the root endpoint returns API information."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert all(
        [
            "name" in data,
            "version" in data,
            "endpoints" in data,
            isinstance(data["endpoints"], list),
        ]
    )


def test_get_all_blocks(client):
    """Test retrieving all blocks in the blockchain."""
    response = client.get("/blocks/")
    assert response.status_code == 200
    data = response.json()
    assert all(
        [
            data["status"] == "success",
            "data" in data,
            "chain" in data["data"],
            "length" in data["data"],
            data["data"]["length"] >= 1,
            len(data["data"]["chain"]) >= 1,
        ]
    )
    genesis = data["data"]["chain"][0]
    assert all([genesis["index"] == 0, genesis["previous_hash"] is None])


def test_get_block_by_index(client):
    """Test retrieving a specific block by index."""
    response = client.get("/blocks/0")
    assert response.status_code == 200
    data = response.json()
    assert all([data["status"] == "success", "data" in data, "block" in data["data"]])
    block = data["data"]["block"]
    assert all(
        [
            block["index"] == 0,
            block["previous_hash"] is None,
            len(block["transactions"]) == 1,
        ]
    )


def test_get_block_not_found(client):
    """Test getting a non-existent block returns 404."""
    response = client.get("/blocks/999")
    assert response.status_code == 404
    data = response.json()
    assert all(
        [
            data["status"] == "error",
            "message" in data,
            "Block not found" in data["message"],
        ]
    )


def test_mine_block_no_transactions(client):
    """Test mining a block with no pending transactions."""
    response = client.post(f"/blocks/mine?miner_address={MINER_ADDRESS}")
    assert response.status_code == 400
    data = response.json()
    assert all(
        [
            data["status"] == "error",
            "No pending transactions to mine" in data["message"],
        ]
    )


def test_mine_block_with_transaction(client):
    """Test mining a block with a pending transaction."""
    tx_data = {
        "sender": SENDER_ADDRESS,
        "recipient": RECIPIENT_ADDRESS,
        "amount": 5.0,
        "message": "Test transaction",
    }
    client.post("/transactions/", json=tx_data)
    response = client.post(f"/blocks/mine?miner_address={MINER_ADDRESS}")
    assert response.status_code == 201
    data = response.json()
    assert all([data["status"] == "success", "data" in data, "block" in data["data"]])
    block = data["data"]["block"]
    assert all([block["index"] == 1, len(block["transactions"]) == 2])
    transaction = block["transactions"][0]
    assert all(
        [
            transaction["sender"] == SENDER_ADDRESS,
            transaction["recipient"] == RECIPIENT_ADDRESS,
            transaction["amount"] == 5.0,
            transaction["status"] == "confirmed",
        ]
    )
    reward = block["transactions"][1]
    assert all(
        [
            reward["sender"] == "0",
            reward["recipient"] == MINER_ADDRESS,
            reward["amount"] == 1.0,
            reward["status"] == "confirmed",
        ]
    )
