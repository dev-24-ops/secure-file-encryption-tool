import os
import base64
import logging
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken

SALT_SIZE = 16        # bytes
ITERATIONS = 390000   # secure default

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

def derive_key(password: bytes, salt: bytes) -> bytes:
    """Derive a secret key from a password and salt using PBKDF2."""
    try:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=ITERATIONS,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        logger.info("Key derived successfully")
        return key
    except Exception as e:
        logger.error(f"Error deriving key: {e}")
        raise

def encrypt_data(data: bytes, key: bytes) -> bytes:
    """Encrypt data using Fernet symmetric encryption."""
    try:
        fernet = Fernet(key)
        encrypted = fernet.encrypt(data)
        logger.info("Data encryption complete")
        return encrypted
    except Exception as e:
        logger.error(f"Encryption failed: {e}")
        raise

def decrypt_data(encrypted: bytes, key: bytes) -> bytes:
    """Decrypt data using Fernet symmetric encryption."""
    try:
        fernet = Fernet(key)
        decrypted = fernet.decrypt(encrypted)
        logger.info("Data decryption complete")
        return decrypted
    except InvalidToken:
        logger.error("Invalid key or password - unable to decrypt")
        raise
    except Exception as e:
        logger.error(f"Decryption failed: {e}")
        raise
