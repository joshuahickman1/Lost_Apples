"""
Generic SearchParty Database Decryptor for iOS 16+ databases

This module provides a generic decryptor for SQLite databases used by iOS searchpartyd.
All searchpartyd databases use the same SQLite Encryption Extension (SEE) with AES-256-OFB.

Supported Databases (iOS 16+):
- Observations.db (key: Observations) - Device observation records with locations
- CloudStorage.db (key: CloudStorage) - Cloud storage data
- CloudStorage_CKRecordCache.db (key: CloudKitCache) - CloudKit record cache
- ItemSharingKeys.db (key: KeyDatabase) - Item sharing key data
- StandaloneBeacon.db (key: StandAloneBeacon) - Standalone beacon data

Encryption Details:
- Method: SQLite Encryption Extension (SEE) with AES-256-OFB
- Page Size: 4096 bytes
- Reserved Area: 12 bytes at end of each page (contains IV/nonce)
- IV Construction: page_number (4 bytes, little-endian) + reserved (12 bytes)
- Header bytes 16-23 are NOT encrypted

WAL Decryption Details:
- The reserved area (IV) must be PRESERVED in decrypted WAL (not zeroed)
- Frame checksums must be RECALCULATED after decryption
- Checksums use native (little-endian) byte order for word interpretation
- Initial checksum values come from WAL header checksum (bytes 24-31)
- Each frame's checksum chains from the previous frame

Reference: https://thebinaryhick.blog/2025/08/19/further-observations-more-on-ios-search-party/
"""

import struct
import shutil
import os
from pathlib import Path
from typing import Dict, Optional, Tuple

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class SearchpartydDatabaseDecryptor:
    """
    Generic decryptor for iOS searchpartyd SQLite databases using SEE AES-256-OFB.
    
    This class can decrypt any searchpartyd database and its WAL file, given the
    appropriate 32-byte encryption key from the iOS keychain.
    """
    
    # Constants
    PAGE_SIZE = 4096
    RESERVED_BYTES = 12  # IV is stored in last 12 bytes of each page
    WAL_HEADER_SIZE = 32
    FRAME_HEADER_SIZE = 24
    SQLITE_MAGIC = b'SQLite format 3\x00'
    
    def __init__(self, key: bytes, db_name: str = "Database"):
        """
        Initialize the decryptor with an encryption key.
        
        Args:
            key: 32-byte AES-256 encryption key from keychain
            db_name: Name of the database (for logging purposes)
        """
        if len(key) != 32:
            raise ValueError(f"Key must be 32 bytes, got {len(key)}")
        self.key = key
        self.db_name = db_name
    
    @staticmethod
    def _wal_checksum(data: bytes, s1: int, s2: int) -> Tuple[int, int]:
        """
        Calculate SQLite WAL checksum.
        
        Uses native (little-endian) byte order for word interpretation.
        Processes two 32-bit words at a time:
          s1 += word1 + s2
          s2 += word2 + s1
        
        This matches the SQLite walChecksumBytes() function when
        nativeCksum is True (which it is for magic 0x377f0682 on
        little-endian systems).
        
        Args:
            data: Data to checksum (must be 8-byte aligned)
            s1: Initial s1 value
            s2: Initial s2 value
        
        Returns:
            (s1, s2) tuple with updated checksum values
        """
        for i in range(0, len(data), 8):
            # Use native (little-endian) byte order
            word1 = struct.unpack('<I', data[i:i+4])[0]
            word2 = struct.unpack('<I', data[i+4:i+8])[0]
            s1 = (s1 + word1 + s2) & 0xFFFFFFFF
            s2 = (s2 + word2 + s1) & 0xFFFFFFFF
        return s1, s2
        
    def decrypt_page(self, page_data: bytes, page_number: int) -> bytes:
        """
        Decrypt a single database page using AES-256-OFB.
        
        Args:
            page_data: Raw encrypted page data (4096 bytes)
            page_number: The page number (1-indexed)
            
        Returns:
            Decrypted page data (4096 bytes)
        """
        if len(page_data) != self.PAGE_SIZE:
            raise ValueError(f"Page must be {self.PAGE_SIZE} bytes, got {len(page_data)}")
        
        # Extract the IV from the reserved area (last 12 bytes)
        reserved = page_data[-self.RESERVED_BYTES:]
        encrypted_content = page_data[:-self.RESERVED_BYTES]
        
        # IV construction: page_number (4 bytes LE) + reserved (12 bytes) = 16 bytes
        iv = struct.pack('<I', page_number) + reserved
        
        # Decrypt using AES-256-OFB
        cipher = Cipher(algorithms.AES(self.key), modes.OFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(encrypted_content) + decryptor.finalize()
        
        # For page 1, restore the unencrypted header bytes 16-23
        if page_number == 1:
            decrypted = decrypted[:16] + page_data[16:24] + decrypted[24:]
        
        # Clear the reserved area (set to zeros for standard SQLite format)
        return decrypted + (b'\x00' * self.RESERVED_BYTES)
    
    def decrypt_database(self, encrypted_db_path: str, output_path: str) -> bool:
        """
        Decrypt an entire SQLite database file.
        
        Args:
            encrypted_db_path: Path to encrypted database
            output_path: Path for decrypted output
            
        Returns:
            True if successful
        """
        with open(encrypted_db_path, 'rb') as f:
            encrypted_db = f.read()
        
        # Validate file size is multiple of page size
        if len(encrypted_db) % self.PAGE_SIZE != 0:
            raise ValueError(f"Database size ({len(encrypted_db)}) is not a multiple of page size ({self.PAGE_SIZE})")
        
        num_pages = len(encrypted_db) // self.PAGE_SIZE
        
        # Decrypt all pages
        decrypted_db = bytearray()
        for page_num in range(1, num_pages + 1):
            page_start = (page_num - 1) * self.PAGE_SIZE
            page_end = page_num * self.PAGE_SIZE
            page_data = encrypted_db[page_start:page_end]
            
            decrypted_page = self.decrypt_page(page_data, page_num)
            decrypted_db.extend(decrypted_page)
        
        # Verify SQLite header
        if decrypted_db[:16] != self.SQLITE_MAGIC:
            raise ValueError(f"Decryption failed for {self.db_name} - invalid SQLite header")
        
        # Write decrypted database with explicit flush to ensure it's persisted to disk
        with open(output_path, 'wb') as f:
            f.write(decrypted_db)
            f.flush()
            os.fsync(f.fileno())  # Force write to disk
        
        return True
    
    def decrypt_wal(self, encrypted_wal_path: str, output_path: str) -> Tuple[bool, int]:
        """
        Decrypt the WAL (Write-Ahead Log) file.
        
        The WAL file contains frames, each with:
        - 24-byte frame header
        - 4096-byte page data (encrypted same as main DB)
        
        For Page 1 entries in WAL, bytes 16-23 are NOT encrypted.
        
        IMPORTANT: Unlike the main database, WAL pages must:
        1. PRESERVE the reserved area (IV) - not zero it out
        2. Have frame checksums RECALCULATED after decryption
        
        The checksum algorithm:
        - Uses native (little-endian) byte order
        - Initial values come from WAL header checksum (bytes 24-31)
        - Each frame's checksum chains from the previous frame
        - Checksum covers frame header bytes 0-7 + page content
        
        Args:
            encrypted_wal_path: Path to encrypted WAL file
            output_path: Path for decrypted output
            
        Returns:
            Tuple of (success, number_of_frames)
        """
        with open(encrypted_wal_path, 'rb') as f:
            encrypted_wal = f.read()
        
        if len(encrypted_wal) < self.WAL_HEADER_SIZE:
            raise ValueError("WAL file too small")
        
        # WAL header (first 32 bytes) is not encrypted
        wal_header = bytearray(encrypted_wal[:self.WAL_HEADER_SIZE])
        
        # Verify WAL magic number (big-endian: 0x377f0682, little-endian: 0x377f0683)
        magic = struct.unpack('>I', wal_header[0:4])[0]
        if magic not in (0x377f0682, 0x377f0683):
            raise ValueError(f"Invalid WAL magic number: {hex(magic)}")
        
        # Get the WAL header checksum (bytes 24-31)
        # This is used as the initial value for frame checksums
        hdr_cksum1 = struct.unpack('>I', wal_header[24:28])[0]
        hdr_cksum2 = struct.unpack('>I', wal_header[28:32])[0]
        
        # Calculate number of frames
        frame_size = self.FRAME_HEADER_SIZE + self.PAGE_SIZE
        wal_data_size = len(encrypted_wal) - self.WAL_HEADER_SIZE
        num_frames = wal_data_size // frame_size
        
        # Start building decrypted WAL
        decrypted_wal = bytearray(wal_header)
        
        # Initial checksum values from WAL header checksum
        prev_s1, prev_s2 = hdr_cksum1, hdr_cksum2
        
        # Process each frame
        for frame_idx in range(num_frames):
            frame_start = self.WAL_HEADER_SIZE + frame_idx * frame_size
            frame_header = bytearray(encrypted_wal[frame_start:frame_start + self.FRAME_HEADER_SIZE])
            page_data = encrypted_wal[frame_start + self.FRAME_HEADER_SIZE:frame_start + frame_size]
            
            # Parse frame header to get page number
            page_number = struct.unpack('>I', frame_header[0:4])[0]
            
            # Decrypt the page (preserving reserved area for WAL)
            is_page_1 = (page_number == 1)
            decrypted_page = self._decrypt_wal_page(page_data, page_number, is_page_1)
            
            # Calculate new checksum for this frame
            # First, checksum frame header bytes 0-7
            s1, s2 = self._wal_checksum(bytes(frame_header[0:8]), prev_s1, prev_s2)
            # Then, checksum the decrypted page data
            s1, s2 = self._wal_checksum(decrypted_page, s1, s2)
            
            # Update frame header with new checksums (stored as big-endian)
            struct.pack_into('>I', frame_header, 16, s1)
            struct.pack_into('>I', frame_header, 20, s2)
            
            # Add frame header and decrypted page to output
            decrypted_wal.extend(frame_header)
            decrypted_wal.extend(decrypted_page)
            
            # Use this frame's checksum as initial for next frame
            prev_s1, prev_s2 = s1, s2
        
        # Write decrypted WAL with explicit flush to ensure it's persisted to disk
        with open(output_path, 'wb') as f:
            f.write(decrypted_wal)
            f.flush()
            os.fsync(f.fileno())  # Force write to disk
        
        # Verify file was actually written
        output_path_obj = Path(output_path)
        if not output_path_obj.exists():
            raise RuntimeError(f"WAL file was not created at {output_path}")
        
        actual_size = output_path_obj.stat().st_size
        expected_size = len(decrypted_wal)
        if actual_size != expected_size:
            raise RuntimeError(f"WAL file size mismatch: expected {expected_size}, got {actual_size}")
        
        return True, num_frames
    
    def _decrypt_wal_page(self, page_data: bytes, page_number: int, is_page_1: bool) -> bytes:
        """
        Decrypt a page from the WAL file.
        
        For Page 1, bytes 16-23 are NOT encrypted.
        
        IMPORTANT: Unlike main database pages, WAL pages must PRESERVE
        the reserved area (IV) for proper checksum calculation and
        SQLite compatibility.
        
        Args:
            page_data: Raw encrypted page data
            page_number: The page number
            is_page_1: Whether this is page 1 (has unencrypted header bytes)
            
        Returns:
            Decrypted page data with preserved reserved area
        """
        # Extract reserved area (IV) - keep it for later
        reserved = page_data[-self.RESERVED_BYTES:]
        encrypted_content = page_data[:-self.RESERVED_BYTES]
        
        # IV construction: page_number (4 bytes LE) + reserved (12 bytes)
        iv = struct.pack('<I', page_number) + reserved
        
        # Decrypt using AES-256-OFB
        cipher = Cipher(algorithms.AES(self.key), modes.OFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(encrypted_content) + decryptor.finalize()
        
        # For page 1, restore unencrypted bytes 16-23
        if is_page_1:
            decrypted = decrypted[:16] + page_data[16:24] + decrypted[24:]
        
        # PRESERVE the reserved area (not zeroing it out!)
        # This is critical for WAL - the reserved area is included in
        # the checksum calculation and must be preserved
        return decrypted + reserved
    
    def decrypt_all(self, db_path: str, output_dir: str, output_prefix: str = None) -> Dict[str, str]:
        """
        Decrypt the database and its WAL file (if present).
        
        Args:
            db_path: Path to encrypted database
            output_dir: Directory for decrypted output files
            output_prefix: Prefix for output files (default: uses db_name)
            
        Returns:
            Dictionary with paths to decrypted files
        """
        db_path = Path(db_path)
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        if output_prefix is None:
            output_prefix = db_path.stem
        
        results = {}
        
        # Decrypt main database
        output_db = output_dir / f"{output_prefix}_decrypted.db"
        self.decrypt_database(str(db_path), str(output_db))
        results['database'] = str(output_db)
        
        # Check for WAL file
        wal_path = db_path.parent / f"{db_path.name}-wal"
        if wal_path.exists():
            output_wal = output_dir / f"{output_prefix}_decrypted.db-wal"
            success, num_frames = self.decrypt_wal(str(wal_path), str(output_wal))
            results['wal'] = str(output_wal)
            results['wal_frames'] = num_frames
        
        # Check for SHM file (doesn't need decryption, but copy it for completeness)
        shm_path = db_path.parent / f"{db_path.name}-shm"
        if shm_path.exists():
            output_shm = output_dir / f"{output_prefix}_decrypted.db-shm"
            shutil.copy(str(shm_path), str(output_shm))
            results['shm'] = str(output_shm)
        
        return results


# Database configuration for iOS 16+ searchpartyd databases
# Maps database filename to (key_service_name, description)
IOS16_DATABASES = {
    'CloudStorage.db': ('CloudStorage', 'Cloud storage data'),
    'CloudStorage_CKRecordCache.db': ('CloudKitCache', 'CloudKit record cache'),
    'ItemSharingKeys.db': ('KeyDatabase', 'Item sharing key data'),
    'StandaloneBeacon.db': ('StandAloneBeacon', 'Standalone beacon data'),
}


def decrypt_ios16_databases(
    keychain_extractor,
    searchpartyd_path: str,
    output_dir: str
) -> Dict[str, Dict]:
    """
    Decrypt all iOS 16+ databases found in the searchpartyd folder.
    
    Args:
        keychain_extractor: An initialized iOSKeychainExtractor with keys parsed
        searchpartyd_path: Path to the searchpartyd folder
        output_dir: Directory for decrypted output files
        
    Returns:
        Dictionary mapping database names to their decryption results
    """
    searchpartyd_path = Path(searchpartyd_path)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    results = {}
    
    for db_filename, (key_service, description) in IOS16_DATABASES.items():
        db_path = searchpartyd_path / db_filename
        
        if not db_path.exists():
            results[db_filename] = {
                'success': False,
                'error': 'Database file not found',
                'skipped': True
            }
            continue
        
        # Get the key for this database
        key = keychain_extractor.get_key_by_service(key_service)
        if not key:
            results[db_filename] = {
                'success': False,
                'error': f'{key_service} key not found in keychain',
                'skipped': True
            }
            continue
        
        try:
            # Create decryptor and decrypt
            decryptor = SearchpartydDatabaseDecryptor(key, db_filename)
            output_prefix = db_path.stem  # e.g., "CloudStorage"
            
            decrypt_results = decryptor.decrypt_all(
                str(db_path),
                str(output_dir),
                output_prefix
            )
            
            results[db_filename] = {
                'success': True,
                'description': description,
                'key_service': key_service,
                **decrypt_results
            }
            
        except Exception as e:
            results[db_filename] = {
                'success': False,
                'error': str(e),
                'description': description,
                'key_service': key_service
            }
    
    return results


# Example usage
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) >= 4:
        key_hex = sys.argv[1]
        db_path = sys.argv[2]
        output_dir = sys.argv[3]
        db_name = sys.argv[4] if len(sys.argv) > 4 else "Database"
        
        key = bytes.fromhex(key_hex)
        decryptor = SearchpartydDatabaseDecryptor(key, db_name)
        
        print(f"Decrypting {db_name}...")
        results = decryptor.decrypt_all(db_path, output_dir)
        
        print(f"\n✓ {db_name} decrypted!")
        for key, value in results.items():
            print(f"  {key}: {value}")
    else:
        print("Usage: python searchpartyd_db_decryptor.py <key_hex> <db_path> <output_dir> [db_name]")
        print("\nExample:")
        print("  python searchpartyd_db_decryptor.py f42ed0b8... CloudStorage.db ./output CloudStorage")
