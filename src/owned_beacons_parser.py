"""
OwnedBeacons Parser
This module parses encrypted .record files from the OwnedBeacons folder.
These files contain information about beacons owned by the device user.
"""

import plistlib
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class OwnedBeaconRecord:
    """Represents a parsed owned beacon record."""
    
    def __init__(self, filename: str):
        """
        Initialize an owned beacon record.
        
        Args:
            filename: The filename (UUID.record)
        """
        self.filename = filename
        self.identifier = None
        self.pairing_date = None
        self.stable_identifier = None
        self.model = None  # Device model (e.g., "AirPods Pro (2nd generation)")
        self.custom_name = None  # Custom name from BeaconNamingRecord
        self.emoji = None  # Emoji from BeaconNamingRecord
        self.raw_data = {}
    
    def __str__(self) -> str:
        """Return a string representation of the record."""
        lines = [
            f"Identifier: {self.identifier or 'Unknown'}",
            f"Model: {self.model or 'Not specified'}",
            f"Custom Name: {self.custom_name or 'Not set'}",
            f"Emoji: {self.emoji or 'None'}",
            f"Pairing Date: {self.pairing_date or 'Unknown'}",
            f"Stable Identifier: {self.stable_identifier or 'Unknown'}"
        ]
        return "\n".join(lines)


class OwnedBeaconsParser:
    """Parser for OwnedBeacons .record files."""
    
    def __init__(self, beacon_store_key: bytes):
        """
        Initialize the parser.
        
        Args:
            beacon_store_key: The 32-byte BeaconStore key from keychain
        """
        if len(beacon_store_key) != 32:
            raise ValueError(f"BeaconStore key must be 32 bytes, got {len(beacon_store_key)}")
        
        self.beacon_store_key = beacon_store_key
        self.aesgcm = AESGCM(beacon_store_key)
    
    def parse_record_file(self, record_path: str) -> Optional[OwnedBeaconRecord]:
        """
        Parse a single .record file.
        
        Args:
            record_path: Path to the .record file
            
        Returns:
            OwnedBeaconRecord object, or None if parsing fails
        """
        path = Path(record_path)
        
        # Extract filename
        filename = path.name
        record = OwnedBeaconRecord(filename)
        
        try:
            # Read the encrypted plist
            with open(record_path, 'rb') as f:
                encrypted_plist = plistlib.load(f)
            
            # Extract encryption components
            # Index 0: Nonce (IV) - 16 bytes
            # Index 1: GCM Tag - 16 bytes  
            # Index 2: Encrypted payload
            nonce = encrypted_plist[0]
            gcm_tag = encrypted_plist[1]
            encrypted_payload = encrypted_plist[2]
            
            # Verify sizes
            if len(nonce) != 16:
                print(f"Warning: Nonce is {len(nonce)} bytes, expected 16")
            if len(gcm_tag) != 16:
                print(f"Warning: GCM tag is {len(gcm_tag)} bytes, expected 16")
            
            # Decrypt using AES-256-GCM
            # In GCM mode, the tag is appended to the ciphertext
            ciphertext_with_tag = encrypted_payload + gcm_tag
            
            try:
                decrypted_data = self.aesgcm.decrypt(nonce, ciphertext_with_tag, None)
            except Exception as e:
                print(f"Decryption failed for {filename}: {str(e)}")
                return None
            
            # Parse the decrypted plist
            decrypted_plist = plistlib.loads(decrypted_data)
            record.raw_data = decrypted_plist
            
            # Extract data from the decrypted plist
            self._extract_record_data(decrypted_plist, record)
            
            return record
            
        except Exception as e:
            print(f"Error parsing {record_path}: {str(e)}")
            return None
    
    def _extract_record_data(self, plist_data: dict, record: OwnedBeaconRecord) -> None:
        """
        Extract relevant data from the decrypted plist.
        
        Args:
            plist_data: The decrypted plist dictionary
            record: The OwnedBeaconRecord object to populate
        """
        # Extract identifier (UUID)
        if 'identifier' in plist_data:
            record.identifier = plist_data['identifier']
        
        # Extract model (e.g., "AirPods Pro (2nd generation)")
        if 'model' in plist_data:
            record.model = plist_data['model']
        
        # Extract pairing date (with iCloud account, not necessarily this device)
        if 'pairingDate' in plist_data:
            record.pairing_date = plist_data['pairingDate']
        
        # Extract stable identifier
        if 'stableIdentifier' in plist_data:
            stable_id = plist_data['stableIdentifier']
            # stableIdentifier is a list, take the first element
            if isinstance(stable_id, list) and len(stable_id) > 0:
                record.stable_identifier = stable_id[0]
            else:
                record.stable_identifier = stable_id
    
    def parse_directory(self, directory_path: str) -> List[OwnedBeaconRecord]:
        """
        Parse all .record files in a directory.
        
        Args:
            directory_path: Path to OwnedBeacons directory, or path to
                          the com.apple.icloud.searchpartyd parent directory
            
        Returns:
            List of successfully parsed OwnedBeaconRecord objects
        """
        records = []
        directory = Path(directory_path)
        
        if not directory.exists():
            print(f"Directory not found: {directory_path}")
            return records
        
        # Check if this is the searchpartyd parent directory
        # If so, navigate to the OwnedBeacons subdirectory
        if directory.name == 'com.apple.icloud.searchpartyd':
            owned_dir = directory / 'OwnedBeacons'
            if owned_dir.exists():
                directory = owned_dir
                print(f"Using subdirectory: {owned_dir}")
            else:
                print(f"OwnedBeacons subdirectory not found in {directory_path}")
                return records
        
        # Find all .record files
        record_files = [f for f in directory.glob("*.record") if f.is_file()]
        
        print(f"Found {len(record_files)} .record files")
        
        for record_file in record_files:
            print(f"Parsing {record_file.name}...")
            record = self.parse_record_file(str(record_file))
            if record:
                records.append(record)
                print(f"  ✓ Successfully parsed")
            else:
                print(f"  ✗ Failed to parse")
        
        return records
    
    def get_beacon_by_identifier(self, identifier: str, records: List[OwnedBeaconRecord]) -> Optional[OwnedBeaconRecord]:
        """
        Find an owned beacon by its identifier UUID.
        
        Args:
            identifier: The UUID to find
            records: List of parsed owned beacon records
            
        Returns:
            OwnedBeaconRecord if found, None otherwise
        """
        for record in records:
            if record.identifier and record.identifier.upper() == identifier.upper():
                return record
        return None
    
    def enrich_with_naming_records(self, owned_records: List[OwnedBeaconRecord], 
                                   naming_records: List) -> List[OwnedBeaconRecord]:
        """
        Add custom names and emojis to OwnedBeaconRecords by matching with BeaconNamingRecords.
        
        This matches the 'identifier' field from OwnedBeacons with the 
        'associated_beacon' field from BeaconNamingRecord.
        
        Args:
            owned_records: List of OwnedBeaconRecord objects
            naming_records: List of BeaconNamingRecord objects
            
        Returns:
            The same list of OwnedBeaconRecord objects, now with custom_name and emoji populated
        """
        # Create a lookup dictionary: associatedBeacon UUID -> (name, emoji)
        naming_lookup = {}
        for naming_record in naming_records:
            if naming_record.associated_beacon:
                # Store the custom name and emoji, using UUID as key
                uuid = str(naming_record.associated_beacon).upper()
                naming_lookup[uuid] = (naming_record.name, naming_record.emoji)
        
        # Match and populate custom names and emojis
        matches_found = 0
        for owned_record in owned_records:
            if owned_record.identifier:
                uuid = str(owned_record.identifier).upper()
                if uuid in naming_lookup:
                    owned_record.custom_name, owned_record.emoji = naming_lookup[uuid]
                    matches_found += 1
        
        print(f"\nMatched {matches_found} custom names to owned beacons")
        return owned_records
    
    def export_to_csv(self, records: List[OwnedBeaconRecord], output_path: str) -> bool:
        """
        Export parsed records to CSV format.
        
        Args:
            records: List of OwnedBeaconRecord objects
            output_path: Path where the CSV file should be saved
            
        Returns:
            True if export successful, False otherwise
        """
        from .export_utils import ExportUtils, OwnedBeaconsExporter
        
        csv_data = OwnedBeaconsExporter.to_csv_format(records)
        return ExportUtils.export_to_csv(csv_data, output_path)


# Example usage
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        # Get key from command line or use default
        if sys.argv[1] == "--key":
            key_hex = sys.argv[2]
            directory_path = sys.argv[3] if len(sys.argv) > 3 else "sample_Files/com.apple.icloud.searchpartyd/OwnedBeacons"
        else:
            from src.keychain_parser import KeychainParser
            
            # Parse keychain to get BeaconStore key
            keychain_parser = KeychainParser(sys.argv[1])
            keys = keychain_parser.parse()
            beacon_key = keychain_parser.get_beacon_store_key()
            
            if not beacon_key:
                print("ERROR: BeaconStore key not found in keychain!")
                sys.exit(1)
            
            key_hex = beacon_key.hex()
            directory_path = sys.argv[2] if len(sys.argv) > 2 else "sample_Files/com.apple.icloud.searchpartyd/OwnedBeacons"
        
        key_bytes = bytes.fromhex(key_hex)
        print(f"BeaconStore key: {len(key_bytes)} bytes\n")
        
        # Parse OwnedBeacons files
        parser = OwnedBeaconsParser(key_bytes)
        records = parser.parse_directory(directory_path)
        
        print(f"\n{'='*60}")
        print(f"Successfully parsed {len(records)} owned beacon records")
        print(f"{'='*60}\n")
        
        # Display results
        for i, record in enumerate(records, 1):
            print(f"{'='*60}")
            print(f"Owned Beacon {i}:")
            print(f"{'='*60}")
            print(record)
            print()
        
        # Offer to export
        print("\n" + "="*60)
        export_choice = input("\nExport to CSV? (y/n): ").strip().lower()
        
        if export_choice == 'y':
            csv_path = input("Enter CSV output path (default: owned_beacons_results.csv): ").strip()
            if not csv_path:
                csv_path = "owned_beacons_results.csv"
            parser.export_to_csv(records, csv_path)
    else:
        print("Usage:")
        print("  With keychain: python owned_beacons_parser.py <keychain.plist> [<OwnedBeacons_directory>]")
        print("  With hex key:  python owned_beacons_parser.py --key <hex_key> [<OwnedBeacons_directory>]")
