from tests import *


def test_get_pending_transactions_empty(client):
    """Test retrieving pending transactions when there are none."""
    response = client.get("/transactions/")
    assert response.status_code == 200
    data = response.json()
    assert all(
        [
            data["status"] == "success",
            "data" in data,
            "pending_transactions" in data["data"],
            len(data["data"]["pending_transactions"]) == 0,
        ]
    )


def test_create_transaction(client):
    """Test creating a new transaction."""
    tx_data = {
        "sender": SENDER_ADDRESS,
        "recipient": RECIPIENT_ADDRESS,
        "amount": 5.0,
        "message": "Test transaction",
    }
    response = client.post("/transactions/", json=tx_data)
    assert response.status_code == 201
    data = response.json()
    assert all(
        [data["status"] == "success", "data" in data, "transaction" in data["data"]]
    )
    transaction = data["data"]["transaction"]
    assert all(
        [
            transaction["sender"] == SENDER_ADDRESS,
            transaction["recipient"] == RECIPIENT_ADDRESS,
            transaction["amount"] == 5.0,
            transaction["message"] == "Test transaction",
            transaction["status"] == "pending",
            transaction["nonce"] == 1,
        ]
    )


def test_create_invalid_transaction(client):
    """Test creating an invalid transaction."""
    tx_data = {"sender": SENDER_ADDRESS, "recipient": RECIPIENT_ADDRESS, "amount": -5.0}
    response = client.post("/transactions/", json=tx_data)
    assert response.status_code == 400
    data = response.json()
    assert all(
        [
            data["status"] == "error",
            "Invalid transaction" in data["message"] or "amount" in data["message"],
        ]
    )


def test_get_pending_transactions_after_adding(client):
    """Test retrieving pending transactions after adding one."""
    tx_data = {"sender": SENDER_ADDRESS, "recipient": RECIPIENT_ADDRESS, "amount": 5.0}
    client.post("/transactions/", json=tx_data)
    response = client.get("/transactions/")
    assert response.status_code == 200
    data = response.json()
    assert all(
        [
            data["status"] == "success",
            "data" in data,
            "pending_transactions" in data["data"],
            len(data["data"]["pending_transactions"]) == 1,
        ]
    )
    transaction = data["data"]["pending_transactions"][0]
    assert all(
        [
            transaction["sender"] == SENDER_ADDRESS,
            transaction["recipient"] == RECIPIENT_ADDRESS,
            transaction["amount"] == 5.0,
            transaction["status"] == "pending",
        ]
    )


def test_get_balance(client):
    """Test retrieving the balance for an address."""
    response = client.get(f"/transactions/balance/{SENDER_ADDRESS}")
    assert response.status_code == 200
    data = response.json()
    assert all(
        [
            data["status"] == "success",
            "data" in data,
            "address" in data["data"],
            "balance" in data["data"],
            data["data"]["address"] == SENDER_ADDRESS,
            data["data"]["balance"] == 0,
        ]
    )
    transaction_data = {
        "sender": SENDER_ADDRESS,
        "recipient": RECIPIENT_ADDRESS,
        "amount": 5.0,
    }
    client.post("/transactions/", json=transaction_data)
    client.post(f"/blocks/mine?miner_address={MINER_ADDRESS}")
    response = client.get(f"/transactions/balance/{SENDER_ADDRESS}")
    data = response.json()
    assert data["data"]["balance"] == -5.0
    response = client.get(f"/transactions/balance/{RECIPIENT_ADDRESS}")
    data = response.json()
    assert data["data"]["balance"] == 5.0
    response = client.get(f"/transactions/balance/{MINER_ADDRESS}")
    data = response.json()
    assert data["data"]["balance"] == 1.0
