"""
=============================================================================
RAKIB EXIF METADATA READER - Forensic Hash Utility Module
Developer: RAKIB HOSSEN
Platform Compatibility: Kali Linux, NetHunter, Termux, Windows, Linux
=============================================================================
This module provides cryptographic hash generation functions (SHA-256, SHA-1,
MD5) for digital forensics integrity verification. Files are read in memory-
efficient chunks to support arbitrarily large image files without exhaustion.
=============================================================================
"""

import hashlib
import os
from typing import Dict, Optional


# Default chunk size for binary stream hashing (64 KB)
BUFFER_SIZE = 65536


def calculate_hashes(file_path: str, chunk_size: int = BUFFER_SIZE) -> Dict[str, str]:
    """
    Computes SHA-256, SHA-1, and MD5 hashes simultaneously in a single file read pass.

    Args:
        file_path (str): Path to the target image file.
        chunk_size (int): Read buffer size in bytes (default: 64 KB).

    Returns:
        dict: Dictionary containing hexadecimal hash values:
              {'sha256': str, 'sha1': str, 'md5': str}

    Raises:
        FileNotFoundError: If the specified file does not exist.
        PermissionError: If the process lacks read permissions.
        IOError: For unexpected input/output errors.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Image file not found: {file_path}")

    if not os.path.isfile(file_path):
        raise IOError(f"Specified path is not a regular file: {file_path}")

    sha256_hash = hashlib.sha256()
    sha1_hash = hashlib.sha1()
    md5_hash = hashlib.md5()

    try:
        with open(file_path, "rb") as f:
            while True:
                data = f.read(chunk_size)
                if not data:
                    break
                sha256_hash.update(data)
                sha1_hash.update(data)
                md5_hash.update(data)

        return {
            "sha256": sha256_hash.hexdigest(),
            "sha1": sha1_hash.hexdigest(),
            "md5": md5_hash.hexdigest(),
        }
    except PermissionError:
        raise PermissionError(f"Read permission denied for: {file_path}")
    except Exception as exc:
        raise IOError(f"Error computing hashes for {file_path}: {exc}") from exc


def get_sha256(file_path: str) -> Optional[str]:
    """
    Convenience helper to retrieve only the SHA-256 checksum of an image.

    Args:
        file_path (str): Path to the image file.

    Returns:
        str: SHA-256 hexadecimal string, or 'Not Available' if calculation fails.
    """
    try:
        return calculate_hashes(file_path)["sha256"]
    except Exception:
        return "Not Available"


def get_sha1(file_path: str) -> Optional[str]:
    """
    Convenience helper to retrieve only the SHA-1 checksum of an image.

    Args:
        file_path (str): Path to the image file.

    Returns:
        str: SHA-1 hexadecimal string, or 'Not Available' if calculation fails.
    """
    try:
        return calculate_hashes(file_path)["sha1"]
    except Exception:
        return "Not Available"


def get_md5(file_path: str) -> Optional[str]:
    """
    Convenience helper to retrieve only the MD5 checksum of an image.

    Args:
        file_path (str): Path to the image file.

    Returns:
        str: MD5 hexadecimal string, or 'Not Available' if calculation fails.
    """
    try:
        return calculate_hashes(file_path)["md5"]
    except Exception:
        return "Not Available"


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        target = sys.argv[1]
        print(f"Hashing: {target}")
        try:
            hashes = calculate_hashes(target)
            for algo, digest in hashes.items():
                print(f"  {algo.upper()}: {digest}")
        except Exception as e:
            print(f"Error: {e}")
    else:
        print("Usage: python3 hash_utils.py <image_path>")
