import os
import datetime
import logging
from typing import Optional
from pathlib import Path

logger = logging.getLogger(__name__)

def get_file_bytes(filepath: str) -> bytes:
    """Read and return file contents as bytes."""
    if not os.path.isfile(filepath):
        logger.error(f"File does not exist: {filepath}")
        raise FileNotFoundError(f"{filepath} not found")
    
    try:
        with open(filepath, 'rb') as f:
            logger.info(f"Reading file: {filepath}")
            return f.read()
    except Exception as e:
        logger.error(f"Error reading file {filepath}: {e}")
        raise

def write_file_bytes(filepath: str, data: bytes) -> None:
    """Write bytes to a file, creating directories if needed."""
    try:
        # Ensure directory exists
        Path(os.path.dirname(filepath)).mkdir(parents=True, exist_ok=True)
        
        with open(filepath, 'wb') as f:
            f.write(data)
        logger.info(f"File written: {filepath}")
    except Exception as e:
        logger.error(f"Failed to write file {filepath}: {e}")
        raise

def get_timestamp() -> str:
    """Generate a timestamp string for file naming."""
    return datetime.datetime.now().strftime("%Y-%m-%d-%H%M%S")

def get_safe_filename(original: str, prefix: str = "", suffix: str = "") -> str:
    """Generate a safe filename with optional prefix and suffix."""
    base, ext = os.path.splitext(original)
    timestamp = get_timestamp()
    return f"{prefix}{base}_{timestamp}{suffix}{ext}"

def check_file_exists(filepath: str) -> bool:
    """Check if a file exists and is accessible."""
    return os.path.isfile(filepath) and os.access(filepath, os.R_OK)
