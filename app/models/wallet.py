import hmac
import os
from typing import Any

import orjson
from Crypto.Hash import keccak
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


class Wallet:
    def __init__(
        self,
        password: str,
        encrypted_key: bytes | None = None,
        private_key_hex: str | None = None,
        verification_salt: bytes | None = None,
    ) -> None:
        """Initialize a [password-protected] wallet with an existing private key or generate a new one."""
        self._verification_salt = verification_salt if verification_salt else os.urandom(16)
        self._password_hash = self._hash_password(password)
        if encrypted_key:
            private_key = self._decrypt_private_key(encrypted_key)
        elif private_key_hex:
            if private_key_hex.startswith("0x"):
                private_key_hex = private_key_hex[2:]
            private_key_value = int(private_key_hex, base=16)
            private_key = ec.derive_private_key(private_key_value, ec.SECP256K1())
        else:
            private_key = ec.generate_private_key(ec.SECP256K1())
        self._encrypted_key = self._encrypt_private_key(private_key)
        self.public_key = private_key.public_key()
        self.address = self._generate_address()
        del private_key

    def _hash_password(self, password: str) -> bytes:
        """Create a hash of the password for key verification."""
        salt = self._verification_salt
        return self._derive_kdf_key(salt, password)

    def _encrypt_private_key(self, private_key: ec.EllipticCurvePrivateKey) -> bytes:
        """Encrypt the private key with a password."""
        salt = self._verification_salt
        hashed_password = self._password_hash
        aesgcm = AESGCM(hashed_password)
        private_key_numbers = private_key.private_numbers()
        private_key_bytes = format(private_key_numbers.private_value, "x").zfill(64).encode()
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, private_key_bytes, None)
        return salt + nonce + ciphertext

    def _decrypt_private_key(self, encrypted_key: bytes) -> ec.EllipticCurvePrivateKey:
        """Decrypt the private key using the password."""
        salt, nonce, ciphertext = encrypted_key[:16], encrypted_key[16:28], encrypted_key[28:]
        hashed_password = self._password_hash
        aesgcm = AESGCM(hashed_password)
        try:
            private_key_bytes = aesgcm.decrypt(nonce, ciphertext, None)
            private_key_value = int(private_key_bytes.decode(), 16)
            return ec.derive_private_key(private_key_value, ec.SECP256K1())
        except Exception as e:
            raise ValueError(f"Failed to decrypt private key: {str(e)}")

    def _derive_kdf_key(self, salt: bytes, password: str) -> bytes:
        """
        Derive a cryptographic key from a password using PBKDF2.

        This method uses PBKDF2 (Password-Based Key Derivation Function 2)
        with HMAC-SHA256 to generate a secure key from the provided password.
        PBKDF2 applies a pseudorandom function to the password with the salt,
        using multiple iterations to increase computational cost and resistance
        to brute-force attacks.
        """
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
        return kdf.derive(password.encode())

    def _generate_address(self) -> str:
        """Generate a wallet address from the public key."""
        public_key_bytes = self.public_key.public_bytes(
            encoding=Encoding.X962, format=PublicFormat.UncompressedPoint
        )[1:]
        hash_bytes = Wallet._get_keccak_hash(public_key_bytes)
        address_value = "0x" + hash_bytes[-20:].hex()
        address = self._apply_eip55_checksum(address_value)
        return address

    def _apply_eip55_checksum(self, address_value: str) -> str:
        """Apply EIP-55 checksum to a generated wallet address."""
        address_value = address_value.lower().replace("0x", "")
        hash_bytes = Wallet._get_keccak_hash(address_value.encode("utf-8"))
        hash_bytes_hex = hash_bytes.hex()
        checksummed_address = "0x"
        for i, char in enumerate(address_value):
            if int(hash_bytes_hex[i], 16) >= 8:
                checksummed_address += char.upper()
            else:
                checksummed_address += char
        return checksummed_address

    @staticmethod
    def _get_keccak_hash(obj: bytes) -> bytes:
        """Return keccak-256 hash for a given bytestring."""
        k = keccak.new(digest_bits=256)
        k.update(obj)
        return k.digest()

    def export_private_key(self, password: str) -> str:
        """Export the private key as a hex string with 0x prefix."""
        if not self._verify_password(password):
            raise ValueError("Failed to export private key. Invalid wallet password.")
        private_key = self._decrypt_private_key(self._encrypted_key)
        private_key_numbers = private_key.private_numbers()
        return "0x" + format(private_key_numbers.private_value, "x").zfill(64)

    def _verify_password(self, password: str) -> bool:
        """Verify if the provided password is correct."""
        try:
            key = self._derive_kdf_key(self._verification_salt, password)
            return hmac.compare_digest(key, self._password_hash)
        except Exception:
            return False

    def get_public_key_hex(self) -> str:
        """Get the public key as a hex string with 0x prefix."""
        public_key_bytes = self.public_key.public_bytes(
            encoding=Encoding.X962, format=PublicFormat.UncompressedPoint
        )
        return "0x" + public_key_bytes.hex()

    def export_encrypted_keystore(self, password: str) -> dict:
        """Export the encrypted keystore for backup or storage."""
        if not self._verify_password(password):
            raise ValueError("Failed to export keystore. Invalid wallet password.")
        return {
            "encrypted_key": self._encrypted_key,
            "verification_salt": self._verification_salt,
        }

    @classmethod
    def restore_from_keystore(cls, keystore: dict, password: str) -> "Wallet":
        """Restore a wallet from an exported keystore."""
        if not isinstance(keystore, dict):
            raise ValueError("Invalid keystore format")
        encrypted_key = keystore.get("encrypted_key")
        verification_salt = keystore.get("verification_salt")
        if not encrypted_key or not verification_salt:
            raise ValueError("Incomplete keystore data")
        return cls(
            password=password,
            encrypted_key=encrypted_key,
            verification_salt=verification_salt,
        )

    def sign_transaction(self, transaction_data: dict, password: str) -> bytes:
        """Sign transaction data with the wallet's private key."""
        if not self._verify_password(password):
            raise ValueError("Failed to sign transaction. Invalid wallet password.")
        data_bytes = orjson.dumps(transaction_data, option=orjson.OPT_SORT_KEYS)
        message_hash = Wallet._get_keccak_hash(data_bytes)
        private_key = self._decrypt_private_key(self._encrypted_key)
        signature = private_key.sign(message_hash, ec.ECDSA(hashes.SHA256()))
        return signature

    @staticmethod
    def verify_signature(transaction_data: dict, signature: bytes, public_key_bytes: bytes) -> bool:
        """Verify a transaction's signature."""
        try:
            data_bytes = orjson.dumps(transaction_data, option=orjson.OPT_SORT_KEYS)
            message_hash = Wallet._get_keccak_hash(obj=data_bytes)
            public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256K1(), public_key_bytes
            )
            public_key.verify(signature, message_hash, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception as e:
            return False
