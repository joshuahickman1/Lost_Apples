"""
WildModeAssociationRecord Parser
This module parses encrypted .record files from the WildModeAssociationRecord folder.
These files contain information about unwanted trackers detected by the iOS device.
"""

import plistlib
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend


class WildModeRecord:
    """Represents a parsed wild mode association record (unwanted tracker)."""
    
    def __init__(self, uuid: str):
        """
        Initialize a wild mode record.
        
        Args:
            uuid: The UUID of the record (filename without .record extension)
        """
        self.uuid = uuid
        self.mac_addresses = []
        self.trigger_datetime = None
        self.locations = []
        self.manufacturer = None
        self.model = None
        self.tracker_uuid = None
        self.first_seen = None
        self.raw_data = {}
        self.ios_format = None  # 'ios17' or 'ios18' to track source format
        self.raw_advertisement = None  # Store raw advertisement data for iOS 17 records
        self.raw_address = None        # Store raw address bytes for iOS 18 records
        self.observation_states = {}  # Dictionary of observation state names to timestamps (e.g., 'update', 'staged', 'notify')
    
    def __str__(self) -> str:
        """Return a string representation of the record."""
        lines = [
            f"UUID: {self.uuid}",
            f"iOS Format: {self.ios_format or 'Unknown'}",
            f"Manufacturer: {self.manufacturer or 'Unknown'}",
            f"Model: {self.model or 'Unknown'}",
            f"Tracker UUID: {self.tracker_uuid or 'Unknown'}",
            f"First Seen: {self.first_seen or 'Unknown'}",
            f"Trigger Date/Time: {self.trigger_datetime or 'Unknown'}",
            f"MAC Addresses: {len(self.mac_addresses)}",
            f"Location Entries: {len(self.locations)}"
        ]
        
        # Add MAC addresses if present
        if self.mac_addresses:
            lines.append("\nMAC Addresses:")
            for mac in self.mac_addresses:
                lines.append(f"  - {mac}")
        
        # Add location details
        if self.locations:
            lines.append("\nLocations:")
            for i, loc in enumerate(self.locations, 1):
                lat = loc.get('latitude', 'Unknown')
                lon = loc.get('longitude', 'Unknown')
                timestamp = loc.get('timestamp', 'Unknown')
                accuracy = loc.get('horizontal_accuracy', 'Unknown')
                
                lines.append(f"  Location {i}:")
                lines.append(f"    Latitude:  {lat}")
                lines.append(f"    Longitude: {lon}")
                lines.append(f"    Timestamp: {timestamp}")
                lines.append(f"    Accuracy:  {accuracy} meters" if accuracy != 'Unknown' else f"    Accuracy:  {accuracy}")
        
        # Add observation states if present
        if self.observation_states:
            lines.append("\nObservation States:")
            for state_name, state_timestamp in self.observation_states.items():
                lines.append(f"  {state_name}: {state_timestamp}")
        
        return "\n".join(lines)


class WildModeParser:
    """Parser for WildModeAssociationRecord .record files."""
    
    # Apple epoch starts at 2001-01-01 00:00:00 UTC
    APPLE_EPOCH = datetime(2001, 1, 1)
    
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
    
    def parse_record_file(self, record_path: str) -> Optional[WildModeRecord]:
        """
        Parse a single .record file.
        
        Args:
            record_path: Path to the .record file
            
        Returns:
            WildModeRecord object, or None if parsing fails
        """
        path = Path(record_path)
        
        # Extract UUID from filename
        uuid = path.stem
        record = WildModeRecord(uuid)
        
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
                print(f"Decryption failed for {uuid}: {str(e)}")
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
    
    def _extract_record_data(self, plist_data: dict, record: WildModeRecord) -> None:
        """
        Extract relevant data from the decrypted plist.
        
        Handles two different iOS formats:
        - iOS 18.x+: Uses 'address' key with direct MAC address data
        - iOS 17.x and below: Uses 'advertisement' key where first 6 bytes are MAC

        Note: iOS 18 records may carry BOTH an 'address' key (6-byte MAC) and an
        'advertisement' key (full 28-byte advertisement key).  When both are present,
        the MAC is derived from 'address' and the full advertisement is captured from
        'advertisement' so that separated-key matching works the same as for iOS 17.
        
        Args:
            plist_data: The decrypted plist dictionary
            record: The WildModeRecord object to populate
        """
        # Extract MAC addresses - handle both iOS 17 and iOS 18 formats
        mac_extracted = False
        
        # iOS 18.x+ format: 'address' key contains the MAC address directly
        if 'address' in plist_data:
            address = plist_data['address']
            # Skip if address is null or a null string (iOS 18 may have both keys)
            if address is not None and address != '$null':
                if isinstance(address, bytes):
                    # Direct bytes format.
                    # Apply the BLE static-random address correction: force the
                    # two most-significant bits of byte 0 to 1 (| 0xC0), matching
                    # how iOS reports the address in Observations.db.
                    corrected = bytes([address[0] | 0xC0]) + address[1:6]
                    mac = self._format_mac_address(corrected)
                    record.mac_addresses.append(mac)
                    record.ios_format = 'iOS 18.x and above'
                    record.raw_address = address  # Store raw bytes for reference
                    mac_extracted = True
                elif isinstance(address, dict) and 'data' in address:
                    # Dictionary format with 'data' key (common iOS 18 format)
                    mac_bytes = address['data']
                    if isinstance(mac_bytes, bytes) and len(mac_bytes) >= 6:
                        # Apply the BLE static-random address correction (| 0xC0)
                        corrected = bytes([mac_bytes[0] | 0xC0]) + mac_bytes[1:6]
                        mac = self._format_mac_address(corrected)
                        record.mac_addresses.append(mac)
                        record.ios_format = 'iOS 18.x and above'
                        record.raw_address = mac_bytes  # Store raw bytes for reference
                        mac_extracted = True
        
        # iOS 17.x and below format: 'advertisement' key contains Bluetooth advertisement
        # The first 6 bytes of the advertisement data are the randomized MAC address
        if not mac_extracted and 'advertisement' in plist_data:
            advertisement = plist_data['advertisement']
            # Skip if advertisement is null or a null string
            if advertisement is not None and advertisement != '$null':
                adv_data = self._extract_advertisement_data(advertisement)
                if adv_data and len(adv_data) >= 6:
                    # First 6 bytes are the MAC address.
                    # BLE static random addresses require the two most significant bits
                    # of the first byte to be set (per the BLE spec). The raw advertisement
                    # data may not have these bits set, so we force them with OR 0xC0.
                    # Example: 0x2B | 0xC0 = 0xEB (the correct first octet).
                    mac_bytes = bytes([adv_data[0] | 0xC0]) + adv_data[1:6]
                    mac = self._format_mac_address(mac_bytes)
                    record.mac_addresses.append(mac)
                    record.ios_format = 'iOS 17.x and below'
                    record.raw_advertisement = adv_data  # Store full advertisement for reference
                    mac_extracted = True

        # iOS 18 records can carry BOTH an 'address' key (6-byte MAC) AND an
        # 'advertisement' key (full 28-byte advertisement key).  The parser
        # already extracted the MAC from 'address' above; now also capture the
        # full advertisement bytes so the exporter can output 28-byte
        # Advertisement_Hex, enabling separated-key matching in Wild Mode
        # comparison (the same path used for iOS 17 records).
        if mac_extracted and record.raw_advertisement is None and 'advertisement' in plist_data:
            advertisement = plist_data['advertisement']
            if advertisement is not None and advertisement != '$null':
                adv_data = self._extract_advertisement_data(advertisement)
                if adv_data and len(adv_data) == 28:
                    record.raw_advertisement = adv_data
        
        # Some records may have multiple addresses in different keys
        if 'addresses' in plist_data:
            for addr in plist_data['addresses']:
                if isinstance(addr, bytes):
                    mac = self._format_mac_address(addr)
                    record.mac_addresses.append(mac)
        
        # Extract trigger date/time
        if 'triggerDate' in plist_data:
            record.trigger_datetime = self._convert_apple_timestamp(plist_data['triggerDate'])
        
        # Extract locations
        if 'locations' in plist_data:
            for loc_data in plist_data['locations']:
                location = self._parse_location(loc_data)
                if location:
                    record.locations.append(location)
        
        # Extract metadata - handle both possible key names
        # Some iOS versions use 'manufacturer'/'model', others use 'manufacturerName'/'modelName'
        if 'manufacturer' in plist_data:
            record.manufacturer = plist_data['manufacturer']
        elif 'manufacturerName' in plist_data:
            record.manufacturer = plist_data['manufacturerName']
        
        if 'model' in plist_data:
            record.model = plist_data['model']
        elif 'modelName' in plist_data:
            record.model = plist_data['modelName']
        
        # Also check inside 'productInfo' dictionary if present
        if 'productInfo' in plist_data and isinstance(plist_data['productInfo'], dict):
            product_info = plist_data['productInfo']
            if not record.manufacturer:
                if 'manufacturerName' in product_info:
                    record.manufacturer = product_info['manufacturerName']
                elif 'manufacturer' in product_info:
                    record.manufacturer = product_info['manufacturer']
            if not record.model:
                if 'modelName' in product_info:
                    record.model = product_info['modelName']
                elif 'model' in product_info:
                    record.model = product_info['model']
        
        if 'uuid' in plist_data:
            record.tracker_uuid = str(plist_data['uuid'])
        
        # Extract first seen time (usually the first location timestamp)
        if record.locations:
            record.first_seen = record.locations[0].get('timestamp')
        
        # Extract observation states (e.g., 'update', 'staged', 'notify' with their timestamps)
        # The observationStates key contains a list that alternates: [key1, value1, key2, value2, ...]
        if 'observationStates' in plist_data:
            obs_states = plist_data['observationStates']
            if isinstance(obs_states, list) and len(obs_states) >= 2:
                # Process pairs: [key, value, key, value, ...]
                for i in range(0, len(obs_states) - 1, 2):
                    state_name = obs_states[i]
                    state_value = obs_states[i + 1]
                    if isinstance(state_name, str) and state_value is not None:
                        # Convert timestamp if needed
                        converted_timestamp = self._convert_apple_timestamp(state_value)
                        record.observation_states[state_name] = converted_timestamp
    
    def _parse_location(self, loc_data: dict) -> Optional[Dict]:
        """
        Parse a location entry.
        
        Args:
            loc_data: Dictionary containing location data
            
        Returns:
            Dictionary with parsed location information
        """
        location = {}
        
        if 'latitude' in loc_data:
            location['latitude'] = loc_data['latitude']
        
        if 'longitude' in loc_data:
            location['longitude'] = loc_data['longitude']
        
        if 'horizontalAccuracy' in loc_data:
            location['horizontal_accuracy'] = loc_data['horizontalAccuracy']
        
        if 'timestamp' in loc_data:
            location['timestamp'] = self._convert_apple_timestamp(loc_data['timestamp'])
        
        return location if location else None
    
    def _extract_advertisement_data(self, advertisement) -> Optional[bytes]:
        """
        Extract raw advertisement data from various formats.
        
        iOS 17.x stores advertisement data in nested dictionaries,
        and the data may be raw bytes or base64 encoded.
        
        Args:
            advertisement: The advertisement data (dict, bytes, or string)
            
        Returns:
            Raw bytes of the advertisement data, or None if extraction fails
        """
        import base64
        
        try:
            # Handle nested dictionary format: {'key': {'data': bytes}}
            if isinstance(advertisement, dict):
                # Check for 'key' -> 'data' nested structure (iOS 17 format)
                if 'key' in advertisement:
                    key_data = advertisement['key']
                    if isinstance(key_data, dict) and 'data' in key_data:
                        return self._decode_advertisement_bytes(key_data['data'])
                    elif isinstance(key_data, bytes):
                        return self._decode_advertisement_bytes(key_data)
                # Check for direct 'data' key
                if 'data' in advertisement:
                    return self._decode_advertisement_bytes(advertisement['data'])
            
            # Handle direct bytes
            if isinstance(advertisement, bytes):
                return self._decode_advertisement_bytes(advertisement)
            
            # Handle base64 string
            if isinstance(advertisement, str) and advertisement != '$null':
                try:
                    return base64.b64decode(advertisement)
                except:
                    pass
            
            return None
            
        except Exception as e:
            print(f"Warning: Could not extract advertisement data: {e}")
            return None
    
    def _decode_advertisement_bytes(self, data) -> Optional[bytes]:
        """
        Decode advertisement data that may be raw bytes or base64 encoded.
        
        Args:
            data: The data to decode (bytes or string)
            
        Returns:
            Raw bytes, or None if decoding fails
        """
        import base64
        
        if isinstance(data, bytes):
            # Check if it might be base64 encoded (ASCII printable characters)
            # Base64 strings typically contain only alphanumeric chars and +/=
            try:
                # If all bytes are ASCII printable and it's a reasonable length,
                # try base64 decoding
                if all(32 <= b < 127 for b in data):
                    decoded = base64.b64decode(data)
                    # If decoded successfully and result is shorter, it was likely base64
                    if len(decoded) < len(data):
                        return decoded
            except:
                pass
            # Return as-is if not base64
            return data
        
        if isinstance(data, str):
            try:
                return base64.b64decode(data)
            except:
                return data.encode('utf-8') if data else None
        
        return None
    
    def _format_mac_address(self, mac_bytes: bytes) -> str:
        """
        Format MAC address bytes as a readable string.
        
        Args:
            mac_bytes: 6-byte MAC address (only first 6 bytes used)
            
        Returns:
            Formatted MAC address string (XX:XX:XX:XX:XX:XX)
        """
        # Ensure we only use the first 6 bytes
        return ':'.join(f'{b:02X}' for b in mac_bytes[:6])
    
    def _convert_apple_timestamp(self, timestamp) -> datetime:
        """
        Convert Apple timestamp to Python datetime.
        Apple uses seconds since 2001-01-01 00:00:00 UTC.
        
        Args:
            timestamp: Apple timestamp (seconds since 2001-01-01) or datetime object
            
        Returns:
            Python datetime object
        """
        from datetime import timedelta
        
        # If it's already a datetime object, return it
        if isinstance(timestamp, datetime):
            return timestamp
        
        # If it's a number (float or int), convert from Apple epoch
        if isinstance(timestamp, (int, float)):
            return self.APPLE_EPOCH + timedelta(seconds=timestamp)
        
        # If we can't convert it, return None
        return None
    
    def parse_directory(self, directory_path: str) -> List[WildModeRecord]:
        """
        Parse all .record files in a directory.
        
        Args:
            directory_path: Path to WildModeAssociationRecord directory, or path to
                          the com.apple.icloud.searchpartyd parent directory
            
        Returns:
            List of successfully parsed WildModeRecord objects
        """
        records = []
        directory = Path(directory_path)
        
        if not directory.exists():
            print(f"Directory not found: {directory_path}")
            return records
        
        # Check if this is the searchpartyd parent directory
        # If so, navigate to the WildModeAssociationRecord subdirectory
        if directory.name == 'com.apple.icloud.searchpartyd':
            wild_mode_dir = directory / 'WildModeAssociationRecord'
            if wild_mode_dir.exists():
                directory = wild_mode_dir
                print(f"Using subdirectory: {wild_mode_dir}")
            else:
                print(f"WildModeAssociationRecord subdirectory not found in {directory_path}")
                return records
        
        # Find all .record files (not subdirectories)
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


    def export_to_csv(self, records: List[WildModeRecord], output_path: str) -> bool:
        """
        Export parsed records to CSV format.
        
        Args:
            records: List of WildModeRecord objects
            output_path: Path where the CSV file should be saved
            
        Returns:
            True if export successful, False otherwise
        """
        from .export_utils import ExportUtils, WildModeExporter
        
        csv_data = WildModeExporter.to_csv_format(records)
        return ExportUtils.export_to_csv(csv_data, output_path)
    
    def export_to_kml(self, records: List[WildModeRecord], output_path: str, name: str = "Tracker Locations") -> bool:
        """
        Export location data to a single combined KML format.
        
        Args:
            records: List of WildModeRecord objects
            output_path: Path where the KML file should be saved
            name: Name for the KML document
            
        Returns:
            True if export successful, False otherwise
        """
        from .export_utils import ExportUtils, WildModeExporter
        
        kml_data = WildModeExporter.to_kml_format(records)
        return ExportUtils.export_to_kml(kml_data, output_path, name)
    
    def export_single_record_to_kml(self, record: WildModeRecord, output_path: str) -> bool:
        """
        Export a single record to its own KML file.
        
        Args:
            record: WildModeRecord object to export
            output_path: Path where the KML file should be saved
            
        Returns:
            True if export successful, False otherwise
        """
        from .export_utils import ExportUtils, WildModeExporter
        
        # Create a name for this KML based on the record
        manufacturer = record.manufacturer or 'Unknown'
        model = record.model or 'Unknown'
        name = f"{manufacturer} {model} - {record.uuid}"
        
        # Convert just this one record to KML format
        kml_data = WildModeExporter.to_kml_format([record])
        return ExportUtils.export_to_kml(kml_data, output_path, name)
    
    def export_all_records_to_individual_kmls(self, records: List[WildModeRecord], output_directory: str) -> int:
        """
        Export each record to its own separate KML file.
        
        Args:
            records: List of WildModeRecord objects
            output_directory: Directory where KML files should be saved
            
        Returns:
            Number of KML files successfully created
        """
        from pathlib import Path
        
        output_dir = Path(output_directory)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        success_count = 0
        
        for record in records:
            # Create filename from UUID
            filename = f"{record.uuid}.kml"
            output_path = output_dir / filename
            
            if self.export_single_record_to_kml(record, str(output_path)):
                success_count += 1
        
        print(f"\nSuccessfully created {success_count} individual KML files in {output_directory}")
        return success_count
    
    def export_single_record_to_csv(self, record: WildModeRecord, output_path: str) -> bool:
        """
        Export a single record to its own CSV file.
        
        Args:
            record: WildModeRecord object to export
            output_path: Path where the CSV file should be saved
            
        Returns:
            True if export successful, False otherwise
        """
        from .export_utils import ExportUtils, WildModeExporter
        
        csv_data = WildModeExporter.to_csv_format_single(record)
        return ExportUtils.export_to_csv(csv_data, output_path)
    
    def export_all_records_to_individual_csvs(self, records: List[WildModeRecord], output_directory: str) -> int:
        """
        Export each record to its own separate CSV file.
        
        Args:
            records: List of WildModeRecord objects
            output_directory: Directory where CSV files should be saved
            
        Returns:
            Number of CSV files successfully created
        """
        from pathlib import Path
        
        output_dir = Path(output_directory)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        success_count = 0
        
        for record in records:
            # Create filename from UUID
            filename = f"{record.uuid}.csv"
            output_path = output_dir / filename
            
            if self.export_single_record_to_csv(record, str(output_path)):
                success_count += 1
        
        print(f"\nSuccessfully created {success_count} individual CSV files in {output_directory}")
        return success_count


# Example usage
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 2:
        from keychain_parser import KeychainParser
        
        # Parse keychain to get BeaconStore key
        keychain_parser = KeychainParser(sys.argv[1])
        keys = keychain_parser.parse()
        beacon_key = keychain_parser.get_beacon_store_key()
        
        if not beacon_key:
            print("ERROR: BeaconStore key not found in keychain!")
            sys.exit(1)
        
        print(f"BeaconStore key found: {len(beacon_key)} bytes\n")
        
        # Parse WildModeAssociationRecord files
        parser = WildModeParser(beacon_key)
        records = parser.parse_directory(sys.argv[2])
        
        print(f"\n{'='*60}")
        print(f"Successfully parsed {len(records)} records")
        print(f"{'='*60}\n")
        
        # Display results
        for i, record in enumerate(records, 1):
            print(f"\n{'='*60}")
            print(f"Record {i}:")
            print(f"{'='*60}")
            print(record)
            
            if record.locations:
                print(f"\nFirst 3 locations:")
                for j, loc in enumerate(record.locations[:3], 1):
                    print(f"  {j}. Lat: {loc['latitude']:.6f}, Lon: {loc['longitude']:.6f}")
                    print(f"     Time: {loc['timestamp']}")
                    print(f"     Accuracy: {loc.get('horizontal_accuracy', 'N/A')} meters")
        
        # Offer to export
        print("\n" + "="*60)
        print("Export options:")
        print("  csv       - Export to individual CSV files (one per UUID)")
        print("  kml       - Export all records to a single KML file")
        print("  kml-split - Export each record to its own KML file (RECOMMENDED)")
        print("  all       - Export individual CSVs and individual KML files")
        print("  no        - Don't export")
        
        export_choice = input("\nExport results: ").strip().lower()
        
        if export_choice in ['csv', 'all']:
            csv_dir = input("Enter CSV output directory (default: wildmode_csv): ").strip()
            if not csv_dir:
                csv_dir = "wildmode_csv"
            parser.export_all_records_to_individual_csvs(records, csv_dir)
        
        if export_choice == 'kml':
            kml_path = input("Enter KML output path (default: wildmode_locations.kml): ").strip()
            if not kml_path:
                kml_path = "wildmode_locations.kml"
            parser.export_to_kml(records, kml_path)
        
        if export_choice in ['kml-split', 'all']:
            kml_dir = input("Enter KML output directory (default: wildmode_kml): ").strip()
            if not kml_dir:
                kml_dir = "wildmode_kml"
            parser.export_all_records_to_individual_kmls(records, kml_dir)
    else:
        print("Usage: python wild_mode_parser.py <keychain.plist> <WildModeAssociationRecord_directory>")
