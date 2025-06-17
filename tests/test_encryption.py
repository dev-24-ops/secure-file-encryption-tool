import os
import tempfile
import pytest
from tools.crypto_utils import derive_key, encrypt_data, decrypt_data
from tools.file_utils import get_file_bytes, write_file_bytes
from cryptography.fernet import Fernet, InvalidToken

def test_key_derivation_consistency():
    """Test that key derivation is consistent with same password and salt."""
    password = b"test_password"
    salt = os.urandom(16)
    
    key1 = derive_key(password, salt)
    key2 = derive_key(password, salt)
    
    assert key1 == key2, "Key derivation should be consistent"

def test_encrypt_decrypt_with_key():
    """Test encryption and decryption using a key."""
    key = Fernet.generate_key()
    test_data = b"Hello, World!"
    
    encrypted = encrypt_data(test_data, key)
    decrypted = decrypt_data(encrypted, key)
    
    assert decrypted == test_data, "Decrypted data should match original"

def test_encrypt_decrypt_with_password():
    """Test encryption and decryption using a password."""
    password = b"test_password"
    salt = os.urandom(16)
    test_data = b"Hello, World!"
    
    key = derive_key(password, salt)
    encrypted = encrypt_data(test_data, key)
    decrypted = decrypt_data(encrypted, key)
    
    assert decrypted == test_data, "Decrypted data should match original"

def test_decrypt_with_wrong_key():
    """Test that decryption fails with wrong key."""
    correct_key = Fernet.generate_key()
    wrong_key = Fernet.generate_key()
    test_data = b"Hello, World!"
    
    encrypted = encrypt_data(test_data, correct_key)
    
    with pytest.raises(InvalidToken):
        decrypt_data(encrypted, wrong_key)

def test_file_operations():
    """Test file read/write operations."""
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        test_data = b"Hello, World!"
        tf.write(test_data)
        tf.flush()
        
        # Test reading
        read_data = get_file_bytes(tf.name)
        assert read_data == test_data, "File read should match written data"
        
        # Test writing
        write_path = tf.name + ".new"
        write_file_bytes(write_path, test_data)
        read_back = get_file_bytes(write_path)
        assert read_back == test_data, "File write/read should preserve data"
        
        # Clean up
        os.unlink(write_path)
    os.unlink(tf.name)

def test_large_file_handling():
    """Test handling of larger files."""
    large_data = os.urandom(1024 * 1024)  # 1MB of random data
    key = Fernet.generate_key()
    
    encrypted = encrypt_data(large_data, key)
    decrypted = decrypt_data(encrypted, key)
    
    assert decrypted == large_data, "Large file encryption/decryption should work correctly"
