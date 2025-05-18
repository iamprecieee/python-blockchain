import copy

import pytest

from app.models import Wallet
from tests import *


def test_wallet_creation(wallet):
    """Test basic wallet creation with a password."""
    assert all(
        [
            wallet._verification_salt is not None,
            wallet._password_hash is not None,
            wallet._encrypted_key is not None,
            wallet.public_key is not None,
            wallet.address is not None,
            wallet.address.startswith("0x"),
            len(wallet.address) == 42,
        ]
    )


def test_create_wallet_from_private_key(wallet):
    """Test creating a wallet from an existing private key."""
    original_wallet = wallet
    private_key = original_wallet.export_private_key(TEST_PASSWORD)
    restored_wallet = Wallet(password=TEST_PASSWORD, private_key_hex=private_key)
    assert all(
        [
            original_wallet.address == restored_wallet.address,
            original_wallet.get_public_key_hex() == restored_wallet.get_public_key_hex(),
        ]
    )


def test_password_verification(wallet):
    """Test that password verification works correctly."""
    assert all(
        [
            wallet._verify_password(TEST_PASSWORD) is True,
            wallet._verify_password("TEST_ALTERNATE_PASSWORD") is False,
            wallet._verify_password("") is False,
        ]
    )


def test_export_private_key(wallet):
    """Test exporting the private key with password."""
    private_key = wallet.export_private_key(TEST_PASSWORD)
    assert all([private_key.startswith("0x"), len(private_key) == 66])
    with pytest.raises(ValueError):
        wallet.export_private_key("TEST_ALTERNATE_PASSWORD")


def test_keystore_export_restore(wallet):
    """Test exporting and importing a wallet via keystore."""
    original_wallet = wallet
    keystore = original_wallet.export_encrypted_keystore(TEST_PASSWORD)
    with pytest.raises(ValueError):
        original_wallet.export_encrypted_keystore("TEST_ALTERNATE_PASSWORD")
    assert all(["encrypted_key" in keystore, "verification_salt" in keystore])
    restored_wallet = Wallet.restore_from_keystore(keystore, TEST_PASSWORD)
    with pytest.raises(ValueError):
        Wallet.restore_from_keystore(keystore="keystore", password=TEST_PASSWORD)
    with pytest.raises(ValueError):
        Wallet.restore_from_keystore(keystore, "TEST_ALTERNATE_PASSWORD")
    assert all(
        [
            restored_wallet.address == original_wallet.address,
            restored_wallet.get_public_key_hex() == original_wallet.get_public_key_hex(),
        ]
    )


def test_address_generation_and_checksum(wallet):
    """Test that address generation and EIP-55 checksum work correctly."""
    address = wallet.address
    assert all([address.startswith("0x"), len(address) == 42])
    address_without_prefix = address[2:]
    assert not (address_without_prefix.islower() or address_without_prefix.isupper())
    rechecksummed = wallet._apply_eip55_checksum(address.lower())
    assert rechecksummed == address


def test_transaction_signing_and_verification(wallet):
    """Test signing and verifying a transaction."""
    transaction_data = {
        "sender": wallet.address,
        "recipient": RECIPIENT_ADDRESS,
        "amount": 1.5,
        "nonce": 1,
        "timestamp": 1630000000,
    }
    with pytest.raises(ValueError):
        wallet.sign_transaction(transaction_data, "TEST_ALTERNATE_PASSWORD")
    signature = wallet.sign_transaction(transaction_data, TEST_PASSWORD)
    assert all([signature is not None, isinstance(signature, bytes)])
    public_key_bytes = bytes.fromhex(wallet.get_public_key_hex()[2:])
    result = Wallet.verify_signature(transaction_data, signature, public_key_bytes)
    assert result is True
    modified_tx = copy.deepcopy(transaction_data)
    modified_tx["amount"] = 2.0
    result = Wallet.verify_signature(modified_tx, signature, public_key_bytes)
    assert result is False
