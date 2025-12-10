"""
FindMyLocated Database Decryptor for iOS FindMy (iOS 17+)

This module decrypts the SQLite Encryption Extension (SEE) encrypted
databases in the com.apple.findmy.findmylocated folder from iOS devices.

Note: These databases are primarily found in iOS 17 and later versions.

Databases handled:
- LocalStorage.db: Device information, friends, and settings
- CloudStorage.db: Fences and friend shared secrets
- CloudStorage_CKRecordCache.db: CloudKit record cache and change tokens

Encryption Details:
- Method: SQLite Encryption Extension (SEE) with AES-256-OFB
- Page Size: 4096 bytes
- Reserved Area: 12 bytes at end of each page (contains IV/nonce)
- IV Construction: page_number (4 bytes, little-endian) + reserved (12 bytes)
- Header bytes 16-23 are NOT encrypted

Keys Required (from keychain):
- LocalStorage key: service "LocalStorage", agrp "com.apple.findmy.findmylocated"
- CloudStorage key: service "CloudStorage", agrp "com.apple.findmy.findmylocated"
- CloudKitCache key: service "CloudKitCache", agrp "com.apple.findmy.findmylocated"

Reference: https://thebinaryhick.blog/2024/09/02/where-the-wild-tags-are-other-airtag-stories/
"""

import struct
import sqlite3
import os
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class FindMyLocatedDecryptor:
    """
    Decrypts databases in the com.apple.findmy.findmylocated folder using SEE AES-256-OFB.
    """
    
    # Constants
    PAGE_SIZE = 4096
    RESERVED_BYTES = 12  # IV is stored in last 12 bytes of each page
    WAL_HEADER_SIZE = 32
    FRAME_HEADER_SIZE = 24
    SQLITE_MAGIC = b'SQLite format 3\x00'
    
    def __init__(self, key: bytes):
        """
        Initialize the decryptor with an encryption key.
        
        Args:
            key: 32-byte AES-256 encryption key from keychain
        """
        if len(key) != 32:
            raise ValueError(f"Key must be 32 bytes, got {len(key)}")
        self.key = key
    
    @staticmethod
    def _wal_checksum(data: bytes, s1: int, s2: int) -> Tuple[int, int]:
        """
        Calculate SQLite WAL checksum.
        
        Uses native (little-endian) byte order for word interpretation.
        
        Args:
            data: Data to checksum (must be 8-byte aligned)
            s1: Initial s1 value
            s2: Initial s2 value
        
        Returns:
            (s1, s2) tuple with updated checksum values
        """
        for i in range(0, len(data), 8):
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
        Decrypt an entire SEE encrypted database file.
        
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
            raise ValueError("Decryption failed - invalid SQLite header")
        
        # Write decrypted database with explicit flush
        with open(output_path, 'wb') as f:
            f.write(decrypted_db)
            f.flush()
            os.fsync(f.fileno())
        
        return True
    
    def decrypt_wal(self, encrypted_wal_path: str, output_path: str) -> Tuple[bool, int]:
        """
        Decrypt the WAL (Write-Ahead Log) file.
        
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
        
        # Verify WAL magic number
        magic = struct.unpack('>I', wal_header[0:4])[0]
        if magic not in (0x377f0682, 0x377f0683):
            raise ValueError(f"Invalid WAL magic number: {hex(magic)}")
        
        # Get the WAL header checksum
        hdr_cksum1 = struct.unpack('>I', wal_header[24:28])[0]
        hdr_cksum2 = struct.unpack('>I', wal_header[28:32])[0]
        
        # Calculate number of frames
        frame_size = self.FRAME_HEADER_SIZE + self.PAGE_SIZE
        wal_data_size = len(encrypted_wal) - self.WAL_HEADER_SIZE
        num_frames = wal_data_size // frame_size
        
        if num_frames == 0:
            # Empty WAL, just copy header
            with open(output_path, 'wb') as f:
                f.write(wal_header)
            return True, 0
        
        # Start building decrypted WAL
        decrypted_wal = bytearray(wal_header)
        
        # Initialize checksum chain
        prev_cksum1 = hdr_cksum1
        prev_cksum2 = hdr_cksum2
        
        # Process each frame
        for frame_idx in range(num_frames):
            frame_start = self.WAL_HEADER_SIZE + frame_idx * frame_size
            frame_header = bytearray(encrypted_wal[frame_start:frame_start + self.FRAME_HEADER_SIZE])
            page_data = encrypted_wal[frame_start + self.FRAME_HEADER_SIZE:frame_start + frame_size]
            
            # Parse frame header to get page number
            page_number = struct.unpack('>I', frame_header[0:4])[0]
            
            # Decrypt the page (preserve reserved area for WAL)
            reserved = page_data[-self.RESERVED_BYTES:]
            encrypted_content = page_data[:-self.RESERVED_BYTES]
            
            iv = struct.pack('<I', page_number) + reserved
            cipher = Cipher(algorithms.AES(self.key), modes.OFB(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_content = decryptor.update(encrypted_content) + decryptor.finalize()
            
            # For page 1, restore unencrypted header bytes
            if page_number == 1:
                decrypted_content = decrypted_content[:16] + page_data[16:24] + decrypted_content[24:]
            
            # Reconstruct page with reserved area preserved
            decrypted_page = decrypted_content + reserved
            
            # Recalculate frame checksum
            s1, s2 = self._wal_checksum(bytes(frame_header[0:8]), prev_cksum1, prev_cksum2)
            s1, s2 = self._wal_checksum(decrypted_page, s1, s2)
            
            # Update frame header with new checksum
            frame_header[16:20] = struct.pack('>I', s1)
            frame_header[20:24] = struct.pack('>I', s2)
            
            # Update chain
            prev_cksum1 = s1
            prev_cksum2 = s2
            
            # Add to output
            decrypted_wal.extend(frame_header)
            decrypted_wal.extend(decrypted_page)
        
        # Write decrypted WAL
        with open(output_path, 'wb') as f:
            f.write(decrypted_wal)
            f.flush()
            os.fsync(f.fileno())
        
        return True, num_frames
    
    def decrypt_all(self, encrypted_db_path: str, output_dir: str) -> Dict[str, Any]:
        """
        Decrypt a database and its associated WAL file if present.
        
        Args:
            encrypted_db_path: Path to encrypted database
            output_dir: Directory for output files
            
        Returns:
            Dictionary with paths to decrypted files
        """
        db_path = Path(encrypted_db_path)
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        
        # Determine output filename
        db_name = db_path.stem
        output_db = out_dir / f"{db_name}_decrypted.db"
        
        results = {}
        
        # Decrypt main database
        self.decrypt_database(str(db_path), str(output_db))
        results['database'] = str(output_db)
        
        # Check for WAL file
        wal_path = Path(str(db_path) + "-wal")
        if wal_path.exists() and wal_path.stat().st_size > self.WAL_HEADER_SIZE:
            output_wal = out_dir / f"{db_name}_decrypted.db-wal"
            success, num_frames = self.decrypt_wal(str(wal_path), str(output_wal))
            if success:
                results['wal'] = str(output_wal)
                results['wal_frames'] = num_frames
        
        return results


class LocalStorageParser:
    """
    Parser for decrypted LocalStorage.db database.
    
    Tables:
    - devices: Information about FindMy-capable devices
    - friends: Friend/family sharing relationships
    - serverSettings: Server configuration
    - OwnerSharedSecrets: Shared secrets for owned devices
    """
    
    def __init__(self, db_path: str):
        """
        Initialize the parser with path to decrypted database.
        
        Args:
            db_path: Path to decrypted LocalStorage.db
        """
        self.db_path = db_path
        self.conn = None
    
    def _connect(self):
        """Open database connection if not already open."""
        if self.conn is None:
            self.conn = sqlite3.connect(self.db_path)
            self.conn.row_factory = sqlite3.Row
    
    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()
            self.conn = None
    
    def get_tables(self) -> List[str]:
        """Get list of tables in the database."""
        self._connect()
        cursor = self.conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        return [row[0] for row in cursor.fetchall()]
    
    def get_table_counts(self) -> Dict[str, int]:
        """Get record counts for each table."""
        self._connect()
        cursor = self.conn.cursor()
        counts = {}
        for table in self.get_tables():
            cursor.execute(f"SELECT COUNT(*) FROM '{table}'")
            counts[table] = cursor.fetchone()[0]
        return counts
    
    def get_devices(self) -> List[Dict[str, Any]]:
        """
        Get all devices from the devices table.
        
        Returns:
            List of device records with decoded fields
        """
        self._connect()
        cursor = self.conn.cursor()
        
        try:
            cursor.execute("SELECT * FROM devices")
            columns = [description[0] for description in cursor.description]
            
            devices = []
            for row in cursor.fetchall():
                device = dict(zip(columns, row))
                devices.append(device)
            
            return devices
        except sqlite3.Error:
            return []
    
    def get_friends(self) -> List[Dict[str, Any]]:
        """
        Get all friends from the friends table.
        
        Returns:
            List of friend records
        """
        self._connect()
        cursor = self.conn.cursor()
        
        try:
            cursor.execute("SELECT * FROM friends")
            columns = [description[0] for description in cursor.description]
            
            friends = []
            for row in cursor.fetchall():
                friend = dict(zip(columns, row))
                friends.append(friend)
            
            return friends
        except sqlite3.Error:
            return []
    
    def get_server_settings(self) -> Dict[str, Any]:
        """
        Get server settings.
        
        Returns:
            Dictionary of server settings
        """
        self._connect()
        cursor = self.conn.cursor()
        
        try:
            cursor.execute("SELECT * FROM serverSettings LIMIT 1")
            columns = [description[0] for description in cursor.description]
            row = cursor.fetchone()
            
            if row:
                return dict(zip(columns, row))
            return {}
        except sqlite3.Error:
            return {}
    
    def export_devices_to_csv(self, output_path: str) -> int:
        """
        Export devices to CSV file.
        
        Args:
            output_path: Path for CSV output
            
        Returns:
            Number of records exported
        """
        import csv
        
        devices = self.get_devices()
        
        if not devices:
            return 0
        
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=devices[0].keys())
            writer.writeheader()
            writer.writerows(devices)
        
        return len(devices)
    
    def export_friends_to_csv(self, output_path: str) -> int:
        """
        Export friends to CSV file.
        
        Args:
            output_path: Path for CSV output
            
        Returns:
            Number of records exported
        """
        import csv
        
        friends = self.get_friends()
        
        if not friends:
            return 0
        
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=friends[0].keys())
            writer.writeheader()
            writer.writerows(friends)
        
        return len(friends)


class CloudStorageParser:
    """
    Parser for decrypted CloudStorage.db database.
    
    Tables:
    - Fence: Geofence locations
    - FriendSharedSecrets: Shared secrets for friend devices
    """
    
    def __init__(self, db_path: str):
        """
        Initialize the parser with path to decrypted database.
        
        Args:
            db_path: Path to decrypted CloudStorage.db
        """
        self.db_path = db_path
        self.conn = None
    
    def _connect(self):
        """Open database connection if not already open."""
        if self.conn is None:
            self.conn = sqlite3.connect(self.db_path)
            self.conn.row_factory = sqlite3.Row
    
    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()
            self.conn = None
    
    def get_tables(self) -> List[str]:
        """Get list of tables in the database."""
        self._connect()
        cursor = self.conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        return [row[0] for row in cursor.fetchall()]
    
    def get_table_counts(self) -> Dict[str, int]:
        """Get record counts for each table."""
        self._connect()
        cursor = self.conn.cursor()
        counts = {}
        for table in self.get_tables():
            cursor.execute(f"SELECT COUNT(*) FROM '{table}'")
            counts[table] = cursor.fetchone()[0]
        return counts
    
    def get_fences(self) -> List[Dict[str, Any]]:
        """
        Get all geofence records.
        
        Returns:
            List of fence records
        """
        self._connect()
        cursor = self.conn.cursor()
        
        try:
            cursor.execute("SELECT * FROM Fence")
            columns = [description[0] for description in cursor.description]
            
            fences = []
            for row in cursor.fetchall():
                fence = dict(zip(columns, row))
                fences.append(fence)
            
            return fences
        except sqlite3.Error:
            return []
    
    def get_friend_shared_secrets(self) -> List[Dict[str, Any]]:
        """
        Get all friend shared secrets.
        
        Returns:
            List of friend shared secret records
        """
        self._connect()
        cursor = self.conn.cursor()
        
        try:
            cursor.execute("SELECT * FROM FriendSharedSecrets")
            columns = [description[0] for description in cursor.description]
            
            secrets = []
            for row in cursor.fetchall():
                secret = dict(zip(columns, row))
                secrets.append(secret)
            
            return secrets
        except sqlite3.Error:
            return []


class CloudKitCacheParser:
    """
    Parser for decrypted CloudStorage_CKRecordCache.db database.
    
    Tables:
    - CKBlobs: CloudKit blob data
    - DatabaseChangeToken: Database sync tokens
    - ZoneChangeToken: Zone sync tokens
    """
    
    def __init__(self, db_path: str):
        """
        Initialize the parser with path to decrypted database.
        
        Args:
            db_path: Path to decrypted CloudStorage_CKRecordCache.db
        """
        self.db_path = db_path
        self.conn = None
    
    def _connect(self):
        """Open database connection if not already open."""
        if self.conn is None:
            self.conn = sqlite3.connect(self.db_path)
            self.conn.row_factory = sqlite3.Row
    
    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()
            self.conn = None
    
    def get_tables(self) -> List[str]:
        """Get list of tables in the database."""
        self._connect()
        cursor = self.conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        return [row[0] for row in cursor.fetchall()]
    
    def get_table_counts(self) -> Dict[str, int]:
        """Get record counts for each table."""
        self._connect()
        cursor = self.conn.cursor()
        counts = {}
        for table in self.get_tables():
            cursor.execute(f"SELECT COUNT(*) FROM '{table}'")
            counts[table] = cursor.fetchone()[0]
        return counts
    
    def get_database_change_tokens(self) -> List[Dict[str, Any]]:
        """
        Get database change tokens.
        
        Returns:
            List of database change token records
        """
        self._connect()
        cursor = self.conn.cursor()
        
        try:
            cursor.execute("SELECT * FROM DatabaseChangeToken")
            columns = [description[0] for description in cursor.description]
            
            tokens = []
            for row in cursor.fetchall():
                token = dict(zip(columns, row))
                tokens.append(token)
            
            return tokens
        except sqlite3.Error:
            return []
    
    def get_zone_change_tokens(self) -> List[Dict[str, Any]]:
        """
        Get zone change tokens.
        
        Returns:
            List of zone change token records
        """
        self._connect()
        cursor = self.conn.cursor()
        
        try:
            cursor.execute("SELECT * FROM ZoneChangeToken")
            columns = [description[0] for description in cursor.description]
            
            tokens = []
            for row in cursor.fetchall():
                token = dict(zip(columns, row))
                tokens.append(token)
            
            return tokens
        except sqlite3.Error:
            return []


def decrypt_findmylocated_folder(keychain_path: str, findmylocated_path: str, 
                                  output_dir: str) -> Dict[str, Any]:
    """
    Convenience function to decrypt all databases in the findmylocated folder.
    
    Args:
        keychain_path: Path to iOS keychain plist
        findmylocated_path: Path to com.apple.findmy.findmylocated folder
        output_dir: Directory for output files
        
    Returns:
        Dictionary with results and paths
    """
    from src.ios_keychain_extractor import iOSKeychainExtractor
    
    results = {
        'success': False,
        'databases': {},
        'errors': []
    }
    
    # Extract keys from keychain
    extractor = iOSKeychainExtractor(keychain_path)
    extractor.parse()
    
    findmy_path = Path(findmylocated_path)
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    
    # Database configurations: (filename, key_getter, parser_class)
    db_configs = [
        ('LocalStorage.db', extractor.get_local_storage_key, LocalStorageParser),
        ('CloudStorage.db', extractor.get_findmylocated_cloud_storage_key, CloudStorageParser),
        ('CloudStorage_CKRecordCache.db', extractor.get_findmylocated_cloudkit_cache_key, CloudKitCacheParser),
    ]
    
    for db_name, key_getter, parser_class in db_configs:
        db_path = findmy_path / db_name
        
        if not db_path.exists():
            results['errors'].append(f"{db_name} not found")
            continue
        
        key = key_getter()
        if not key:
            results['errors'].append(f"Key for {db_name} not found in keychain")
            continue
        
        try:
            decryptor = FindMyLocatedDecryptor(key)
            decrypt_result = decryptor.decrypt_all(str(db_path), str(out_dir))
            
            # Get table info
            parser = parser_class(decrypt_result['database'])
            decrypt_result['tables'] = parser.get_table_counts()
            parser.close()
            
            results['databases'][db_name] = decrypt_result
            
        except Exception as e:
            results['errors'].append(f"Failed to decrypt {db_name}: {str(e)}")
    
    results['success'] = len(results['databases']) > 0
    return results


# Command-line interface
if __name__ == "__main__":
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Decrypt iOS FindMyLocated databases (iOS 17+)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Decrypt all databases in findmylocated folder using keychain
  python -m src.findmylocated_decryptor keychain.plist ./findmylocated/ ./output
  
  # Decrypt a single database using hex key directly
  python -m src.findmylocated_decryptor --key 01064f7b... --single LocalStorage.db ./output
  
  # List available keys in keychain
  python -m src.findmylocated_decryptor --list-keys keychain.plist

Database Files (iOS 17+):
  LocalStorage.db             - Device info, friends, settings
  CloudStorage.db             - Geofences, friend shared secrets  
  CloudStorage_CKRecordCache.db - CloudKit sync tokens
        """
    )
    
    parser.add_argument('keychain_or_key', nargs='?', 
                        help='Keychain plist path OR encryption key (with --key flag)')
    parser.add_argument('findmylocated_path', nargs='?',
                        help='Path to findmylocated folder OR single database (with --single)')
    parser.add_argument('output_dir', nargs='?',
                        help='Directory for decrypted output')
    parser.add_argument('--key', action='store_true', 
                        help='Treat first argument as hex key instead of keychain path')
    parser.add_argument('--single', action='store_true',
                        help='Decrypt a single database file (requires --key)')
    parser.add_argument('--list-keys', action='store_true',
                        help='List available keys in keychain and exit')
    parser.add_argument('--query', action='store_true',
                        help='Run queries and display sample data')
    parser.add_argument('--export-csv', action='store_true',
                        help='Export data to CSV files')
    
    args = parser.parse_args()
    
    try:
        # List keys mode
        if args.list_keys:
            if not args.keychain_or_key:
                print("ERROR: Keychain path required for --list-keys")
                sys.exit(1)
            
            from src.ios_keychain_extractor import iOSKeychainExtractor
            
            print(f"Extracting keys from keychain...")
            extractor = iOSKeychainExtractor(args.keychain_or_key)
            extractor.parse()
            
            print(f"\nFindMyLocated folder keys (iOS 17+):")
            local_key = extractor.get_local_storage_key()
            cloud_key = extractor.get_findmylocated_cloud_storage_key()
            ck_key = extractor.get_findmylocated_cloudkit_cache_key()
            
            print(f"  LocalStorage: {'✓ ' + local_key.hex()[:24] + '...' if local_key else '✗ Not found'}")
            print(f"  CloudStorage: {'✓ ' + cloud_key.hex()[:24] + '...' if cloud_key else '✗ Not found'}")
            print(f"  CloudKitCache: {'✓ ' + ck_key.hex()[:24] + '...' if ck_key else '✗ Not found'}")
            
            print(f"\nSearchpartyd folder keys:")
            sp_cloud_key = extractor.get_searchpartyd_cloud_storage_key()
            sp_ck_key = extractor.get_searchpartyd_cloudkit_cache_key()
            
            print(f"  CloudStorage: {'✓ ' + sp_cloud_key.hex()[:24] + '...' if sp_cloud_key else '✗ Not found'}")
            print(f"  CloudKitCache: {'✓ ' + sp_ck_key.hex()[:24] + '...' if sp_ck_key else '✗ Not found'}")
            
            sys.exit(0)
        
        # Validate required arguments
        if not all([args.keychain_or_key, args.findmylocated_path, args.output_dir]):
            parser.print_help()
            sys.exit(1)
        
        output_dir = Path(args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Single database mode
        if args.single:
            if not args.key:
                print("ERROR: --single requires --key flag with hex key")
                sys.exit(1)
            
            key = bytes.fromhex(args.keychain_or_key)
            print(f"Using provided key: {key.hex()[:16]}...")
            
            decryptor = FindMyLocatedDecryptor(key)
            results = decryptor.decrypt_all(args.findmylocated_path, str(output_dir))
            
            print(f"✓ Database decrypted: {results['database']}")
            if 'wal' in results:
                print(f"✓ WAL decrypted: {results['wal']} ({results['wal_frames']} frames)")
            
            sys.exit(0)
        
        # Full folder decryption mode
        print(f"Decrypting findmylocated folder (iOS 17+)...")
        results = decrypt_findmylocated_folder(
            args.keychain_or_key,
            args.findmylocated_path,
            str(output_dir)
        )
        
        print(f"\n{'='*60}")
        print("Decryption Results")
        print(f"{'='*60}")
        
        for db_name, db_result in results['databases'].items():
            print(f"\n{db_name}:")
            print(f"  ✓ Decrypted: {db_result['database']}")
            if 'wal' in db_result:
                print(f"  ✓ WAL: {db_result['wal']} ({db_result['wal_frames']} frames)")
            print(f"  Tables:")
            for table, count in db_result['tables'].items():
                print(f"    - {table}: {count} records")
        
        if results['errors']:
            print(f"\nErrors:")
            for error in results['errors']:
                print(f"  ✗ {error}")
        
        # Query mode
        if args.query and 'LocalStorage.db' in results['databases']:
            print(f"\n{'='*60}")
            print("Sample Data from LocalStorage.db")
            print(f"{'='*60}")
            
            parser = LocalStorageParser(results['databases']['LocalStorage.db']['database'])
            
            devices = parser.get_devices()
            print(f"\nDevices ({len(devices)}):")
            for device in devices[:5]:
                name = device.get('deviceName', 'Unknown')
                identifier = device.get('deviceIdentifier', 'Unknown')[:30]
                is_this = "← This Device" if device.get('isThisDevice') else ""
                print(f"  - {name} ({identifier}...) {is_this}")
            
            friends = parser.get_friends()
            print(f"\nFriends ({len(friends)}):")
            for friend in friends[:5]:
                print(f"  - {friend}")
            
            parser.close()
        
        # CSV export mode
        if args.export_csv and 'LocalStorage.db' in results['databases']:
            parser = LocalStorageParser(results['databases']['LocalStorage.db']['database'])
            
            devices_csv = output_dir / "devices.csv"
            count = parser.export_devices_to_csv(str(devices_csv))
            print(f"\n✓ Exported {count} devices to {devices_csv}")
            
            friends_csv = output_dir / "friends.csv"
            count = parser.export_friends_to_csv(str(friends_csv))
            print(f"✓ Exported {count} friends to {friends_csv}")
            
            parser.close()
        
        print(f"\n✓ Decryption complete!")
        
    except Exception as e:
        print(f"ERROR: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
