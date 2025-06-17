"""
Secure File Encryption Tool package.
Provides utilities for file encryption and decryption using both password-based
and key-file methods.
"""

from .crypto_utils import encrypt_data, decrypt_data, derive_key
from .file_utils import get_file_bytes, write_file_bytes, get_timestamp, get_safe_filename

__version__ = '1.0.0'
__all__ = [
    'encrypt_data',
    'decrypt_data',
    'derive_key',
    'get_file_bytes',
    'write_file_bytes',
    'get_timestamp',
    'get_safe_filename'
]
