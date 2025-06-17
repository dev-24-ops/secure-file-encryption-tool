import argparse
import getpass
import os
import logging
from typing import Optional
from .crypto_utils import derive_key, encrypt_data, decrypt_data
from .file_utils import get_file_bytes, write_file_bytes, get_safe_filename
from cryptography.fernet import Fernet

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class EncryptionTool:
    @staticmethod
    def generate_key_file(keyfile: str) -> None:
        """Generate a new key file for encryption/decryption."""
        try:
            key = Fernet.generate_key()
            write_file_bytes(keyfile, key)
            logger.info(f"Key file generated successfully: {keyfile}")
        except Exception as e:
            logger.error(f"Failed to generate key file: {e}")
            raise

    @staticmethod
    def encrypt_file(
        filepath: str,
        key: Optional[bytes] = None,
        password: Optional[bytes] = None,
        output_dir: Optional[str] = None
    ) -> str:
        """
        Encrypt a file using either a key or password.
        Returns the path to the encrypted file.
        """
        try:
            data = get_file_bytes(filepath)
            salt = b""
            
            if password:
                salt = os.urandom(16)  # Generate salt for password-based encryption
                key = derive_key(password, salt)
            
            encrypted = encrypt_data(data, key)
            
            # Prepare output path
            output_path = output_dir if output_dir else os.path.dirname(filepath)
            filename = get_safe_filename(
                os.path.basename(filepath),
                suffix="_encrypted",
                prefix=""
            ) + ".enc"
            output_file = os.path.join(output_path, filename)
            
            # Write encrypted data with salt if password was used
            write_file_bytes(output_file, salt + encrypted if salt else encrypted)
            
            logger.info(f"File encrypted successfully: {output_file}")
            return output_file
            
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise

    @staticmethod
    def decrypt_file(
        filepath: str,
        key: Optional[bytes] = None,
        password: Optional[bytes] = None,
        output_dir: Optional[str] = None
    ) -> str:
        """
        Decrypt a file using either a key or password.
        Returns the path to the decrypted file.
        """
        try:
            data = get_file_bytes(filepath)
            
            if password:
                if len(data) < 16:
                    raise ValueError("Invalid encrypted file format")
                salt = data[:16]
                encrypted = data[16:]
                key = derive_key(password, salt)
            else:
                encrypted = data
            
            decrypted = decrypt_data(encrypted, key)
            
            # Prepare output path
            output_path = output_dir if output_dir else os.path.dirname(filepath)
            filename = get_safe_filename(
                os.path.basename(filepath),
                suffix="_decrypted",
                prefix=""
            )
            if filename.endswith('.enc'):
                filename = filename[:-4]  # Remove .enc extension
            
            output_file = os.path.join(output_path, filename)
            write_file_bytes(output_file, decrypted)
            
            logger.info(f"File decrypted successfully: {output_file}")
            return output_file
            
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise

def main():
    parser = argparse.ArgumentParser(
        description="Secure File Encryption/Decryption Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    # Generate key command
    gen_parser = subparsers.add_parser("genkey", help="Generate a new key file")
    gen_parser.add_argument("keyfile", help="Output key file path")
    
    # Encrypt command
    enc_parser = subparsers.add_parser("encrypt", help="Encrypt a file")
    enc_parser.add_argument("file", help="File to encrypt")
    enc_parser.add_argument("--output-dir", help="Output directory (optional)")
    key_group = enc_parser.add_mutually_exclusive_group(required=True)
    key_group.add_argument("--key-file", help="Key file to use for encryption")
    key_group.add_argument("--password", action="store_true", help="Use password for encryption")
    
    # Decrypt command
    dec_parser = subparsers.add_parser("decrypt", help="Decrypt a file")
    dec_parser.add_argument("file", help="File to decrypt")
    dec_parser.add_argument("--output-dir", help="Output directory (optional)")
    key_group = dec_parser.add_mutually_exclusive_group(required=True)
    key_group.add_argument("--key-file", help="Key file to use for decryption")
    key_group.add_argument("--password", action="store_true", help="Use password for decryption")
    
    args = parser.parse_args()
    tool = EncryptionTool()
    
    try:
        if args.command == "genkey":
            tool.generate_key_file(args.keyfile)
            
        elif args.command in ["encrypt", "decrypt"]:
            key = None
            password = None
            
            if args.password:
                password = getpass.getpass("Enter password: ").encode()
                if args.command == "decrypt":
                    # For decryption, verify password
                    verify = getpass.getpass("Verify password: ").encode()
                    if password != verify:
                        logger.error("Passwords do not match")
                        return 1
            else:
                key = get_file_bytes(args.key_file)
            
            if args.command == "encrypt":
                tool.encrypt_file(args.file, key=key, password=password, output_dir=args.output_dir)
            else:
                tool.decrypt_file(args.file, key=key, password=password, output_dir=args.output_dir)
                
    except Exception as e:
        logger.error(f"Operation failed: {str(e)}")
        return 1
        
    return 0

if __name__ == "__main__":
    exit(main())
