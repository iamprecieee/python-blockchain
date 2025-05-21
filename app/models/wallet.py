import os

import orjson
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


class Wallet:
    """🔐 Wallet implementation (password-protected) for blockchain users 🔐"""

    def __init__(
        self,
        password: str,
        encrypted_key: bytes | None = None,
        private_key_hex: str | None = None,
        verification_salt: bytes | None = None,
    ) -> None:
        """🛡️ Initialize a password-protected wallet with an existing or new private key 🛡️"""
        self._verification_salt = verification_salt if verification_salt else os.urandom(16)
        self._validate_password_strength(password)
        self._password_hash = self._hash_password(password)

        if encrypted_key:
            private_key = self._decrypt_private_key(encrypted_key)
        elif private_key_hex:
            if private_key_hex.startswith("0x"):
                private_key_hex = private_key_hex[2:]

            self._validate_private_key_strength(private_key_hex)
            private_key_value = int(private_key_hex, base=16)
            private_key = ec.derive_private_key(private_key_value, ec.SECP256K1())
        else:
            private_key = self._generate_validated_private_key()

        self._encrypted_key = self._encrypt_private_key(private_key)
        self.public_key = private_key.public_key()
        self.address = self._generate_address()

        del private_key

    def _hash_password(self, password: str) -> bytes:
        """🔐 Create a hash of the password for key verification 🔐"""
        salt = self._verification_salt
        return self._derive_kdf_key(salt, password)

    def _encrypt_private_key(self, private_key: ec.EllipticCurvePrivateKey) -> bytes:
        """🔒 Encrypt the private key (bytes) with a password using AES-GCM encryption 🔒"""
        salt = self._verification_salt
        hashed_password = self._password_hash
        aesgcm = AESGCM(hashed_password)
        private_key_numbers = private_key.private_numbers()
        private_key_bytes = format(private_key_numbers.private_value, "x").zfill(64).encode()
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, private_key_bytes, None)

        return salt + nonce + ciphertext

    def _decrypt_private_key(self, encrypted_key: bytes) -> ec.EllipticCurvePrivateKey:
        """🔓 Decrypt the private key from an encrypted blob using the password 🔓"""
        _, nonce, ciphertext = encrypted_key[:16], encrypted_key[16:28], encrypted_key[28:]
        hashed_password = self._password_hash
        aesgcm = AESGCM(hashed_password)
        try:
            private_key_bytes = aesgcm.decrypt(nonce, ciphertext, None)
            private_key_value = int(private_key_bytes.decode(), 16)

            return ec.derive_private_key(private_key_value, ec.SECP256K1())

        except Exception as e:
            raise ValueError(f"Failed to decrypt private key: {str(e)}") from e

    def _validate_private_key_strength(self, private_key_hex: str) -> None:
        """📏 Validate that the private key has sufficient entropy 📏"""
        import itertools

        private_key_value = int(private_key_hex, 16)
        binary_representation = bin(private_key_value)[2:].zfill(256)
        ones_count = binary_representation.count("1")
        subpatterns = self._detect_subpatterns(binary_representation)
        max_consecutive_bits = max(
            len(list(g)) for _, g in itertools.groupby(binary_representation)
        )

        if any(
            [
                len(private_key_hex) < 64,
                private_key_value < 10**50,
                100 > ones_count > 156,
                subpatterns,
                max_consecutive_bits > 16,
            ]
        ):
            raise ValueError("Invalid private key detected")

    def _derive_kdf_key(self, salt: bytes, password: str) -> bytes:
        """🔑 Derive a cryptographic key from a password using PBKDF2 🔑"""
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
        return kdf.derive(password.encode())

    def _generate_address(self) -> str:
        """📝 Generate a wallet address from the public key (using EIP-55 checksum) 📝"""
        public_key_bytes = self.public_key.public_bytes(
            encoding=Encoding.X962, format=PublicFormat.UncompressedPoint
        )[
            1:
        ]  # skip the 0x04 prefix
        hashed_public_key_bytes = Wallet._get_keccak_hash(public_key_bytes)
        address_value = "0x" + hashed_public_key_bytes[-20:].hex()
        address = self._apply_eip55_checksum(address_value)

        return address

    def _apply_eip55_checksum(self, address_value: str) -> str:
        """✍️ Apply EIP-55 checksum to a generated wallet address ✍️"""
        address_value = address_value.lower().replace("0x", "")
        hashed_address_value_bytes = Wallet._get_keccak_hash(address_value.encode("utf-8"))
        hashed_bytes_hex = hashed_address_value_bytes.hex()
        checksummed_address = "0x"

        for i, char in enumerate(address_value):
            if int(hashed_bytes_hex[i], 16) >= 8:
                checksummed_address += char.upper()
            else:
                checksummed_address += char

        return checksummed_address

    @staticmethod
    def _get_keccak_hash(obj: bytes) -> bytes:
        """🔐 Return keccak-256 hash for a given bytestring 🔐"""
        from Crypto.Hash import keccak

        k = keccak.new(digest_bits=256)
        k.update(obj)

        return k.digest()

    def _verify_password(self, password: str) -> bool:
        """✅ Verify that the provided password is correct ✅"""
        import hmac

        self._validate_password_strength(password)
        try:
            key = self._derive_kdf_key(self._verification_salt, password)
            return hmac.compare_digest(key, self._password_hash)

        except Exception:
            return False

    def _detect_subpatterns(self, binary_str: str) -> bool:
        """🔍 Detect repeating patterns in binary string that might indicate low entropy 🔍"""
        for pattern_length in range(16, 33):
            for i in range(len(binary_str) - pattern_length * 2):
                pattern = binary_str[i : i + pattern_length]
                rest = binary_str[i + pattern_length :]
                if pattern in rest:
                    return True
        return False

    def _generate_validated_private_key(self) -> ec.EllipticCurvePrivateKey:
        """🔑 Generate a private key with enhanced entropy that passes validation 🔑"""
        import hashlib
        import time

        max_attempts = 5

        for _attempt in range(max_attempts):
            entropy_sources = []
            entropy_sources.append(os.urandom(32))
            entropy_sources.append(str(time.time_ns()).encode())
            entropy_sources.append(str(id({})).encode())

            combined_entropy = hashlib.sha3_512(b"".join(entropy_sources)).digest()

            curve = ec.SECP256K1()
            temp_key = ec.generate_private_key(curve)
            temp_num = temp_key.private_numbers().private_value

            entropy_int = int.from_bytes(combined_entropy, byteorder="big")
            valid_key_value = (entropy_int % (temp_num - 1)) + 1

            candidate_key = ec.derive_private_key(valid_key_value, curve)

            private_hex = format(valid_key_value, "x").zfill(64)
            try:
                self._validate_private_key_strength(private_hex)
                return candidate_key

            except ValueError:
                continue

        return ec.generate_private_key(ec.SECP256K1())

    def _validate_password_strength(self, password: str) -> None:
        """📏 Check if password meets minimum security requirements 📏"""
        has_lowercase = any(char.islower() for char in password)
        has_uppercase = any(char.isupper() for char in password)
        has_digit = any(char.isdigit() for char in password)
        has_special = any(not char.isalnum() for char in password)
        character_type_count = sum([has_lowercase, has_uppercase, has_digit, has_special])
        if any([" " in password, len(password) < 8, character_type_count < 3]):
            raise ValueError("Invalid password detected")

        index = 0
        while index < len(password) > index + 2:
            if password[index] == password[index + 1] == password[index + 2]:
                raise ValueError("Invalid password detected")
            index += 1

    def get_public_key_hex(self) -> str:
        """🔍 Get the public key as a hex string with 0x prefix 🔍"""
        public_key_bytes = self.public_key.public_bytes(
            encoding=Encoding.X962, format=PublicFormat.UncompressedPoint
        )
        return "0x" + public_key_bytes.hex()

    def export_private_key(self, password: str) -> str:
        """✍️ Export the private key as a hex string with 0x prefix ✍️"""
        if not self._verify_password(password):
            raise ValueError("Failed to export private key. Invalid wallet password.")

        private_key = self._decrypt_private_key(self._encrypted_key)
        private_key_numbers = private_key.private_numbers()

        return "0x" + format(private_key_numbers.private_value, "x").zfill(64)

    def export_encrypted_keystore(self, password: str) -> dict:
        """✍️ Export the encrypted keystore for backup or storage ✍️"""
        if not self._verify_password(password):
            raise ValueError("Failed to export keystore. Invalid wallet password.")

        return {
            "encrypted_key": self._encrypted_key,
            "verification_salt": self._verification_salt,
        }

    @classmethod
    def restore_from_keystore(cls, keystore: dict, password: str) -> "Wallet":
        """🔄 Restore a wallet from an exported keystore 🔄"""
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
        """✍️ Sign transaction data with the wallet's private key ✍️"""
        if not self._verify_password(password):
            raise ValueError("Failed to sign transaction. Invalid wallet password.")

        data_bytes = orjson.dumps(transaction_data, option=orjson.OPT_SORT_KEYS)
        message_hash = Wallet._get_keccak_hash(data_bytes)
        private_key = self._decrypt_private_key(self._encrypted_key)
        signature = private_key.sign(message_hash, ec.ECDSA(hashes.SHA256()))

        return signature

    @staticmethod
    def verify_signature(transaction_data: dict, signature: bytes, public_key_bytes: bytes) -> bool:
        """✅ Verify a transaction's signature ✅"""
        try:
            data_bytes = orjson.dumps(transaction_data, option=orjson.OPT_SORT_KEYS)
            message_hash = Wallet._get_keccak_hash(obj=data_bytes)
            public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256K1(), public_key_bytes
            )
            public_key.verify(signature, message_hash, ec.ECDSA(hashes.SHA256()))

            return True

        except Exception:
            return False
