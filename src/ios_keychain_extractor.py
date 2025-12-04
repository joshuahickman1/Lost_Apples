"""
iOS Keychain Extractor for searchpartyd
This module extracts encryption keys from encrypted iOS keychain files following the structure:
- classKeyIdxToUnwrappedMetadataClassKey: dict mapping indices to class keys
- keychainEntries: list of entries with encrypted data and metadata
- Multi-stage decryption using AES-GCM

Supports both iOS 17.5+ (key in data - v_Data) and iOS < 17.5 (key in metadata - gena)
"""

import plistlib
from typing import Dict, Optional, List
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class KeychainEntry:
    """Represents a single keychain entry with its encrypted components."""
    
    def __init__(self, entry_dict: dict):
        """
        Initialize a keychain entry from a dictionary.
        
        Args:
            entry_dict: Dictionary containing the keychain entry data
        """
        self.class_key_idx = entry_dict.get('classKeyIdx')
        self.data_dict = entry_dict.get('data', {})
        self.metadata_dict = entry_dict.get('metadata', {})
        self.row_id = entry_dict.get('rowID')
        self.table = entry_dict.get('table')
        
        # Extract encrypted components
        self.data_ciphertext = self.data_dict.get('ciphertext')
        self.data_unwrapped_key = self.data_dict.get('unwrappedKey')
        
        self.metadata_ciphertext = self.metadata_dict.get('ciphertext')
        self.metadata_wrapped_key = self.metadata_dict.get('wrappedKey')
        
        # Decoded components (will be filled during parsing)
        self.metadata_key: Optional[bytes] = None
        self.metadata_content: Optional[dict] = None
        self.metadata_plaintext: Optional[bytes] = None
        self.actual_key: Optional[bytes] = None
        self.service_name: Optional[str] = None
        
    def __repr__(self):
        return f"KeychainEntry(rowID={self.row_id}, classKeyIdx={self.class_key_idx}, table={self.table})"


class iOSKeychainExtractor:
    """
    Extracts encryption keys from iOS keychain files.
    
    This parser handles the multi-stage decryption process:
    1. Use class key to decrypt wrappedKey → get metadata key
    2. Use metadata key to decrypt metadata ciphertext → get service info
    3. Try to extract key from data (iOS 17.5+) OR metadata (iOS < 17.5)
    """
    
    def __init__(self, keychain_path: str):
        """
        Initialize the keychain extractor.
        
        Args:
            keychain_path: Path to the keychain plist file
        """
        self.keychain_path = keychain_path
        self.class_keys: Dict[int, bytes] = {}
        self.entries: List[KeychainEntry] = []
        self.extracted_keys: Dict[str, bytes] = {}
        
    def parse(self) -> Dict[str, bytes]:
        """
        Parse the keychain file and extract all keys.
        
        Returns:
            Dictionary mapping service names to their encryption keys
            
        Raises:
            FileNotFoundError: If keychain file doesn't exist
            Exception: If parsing or decryption fails
        """
        # Load the plist file
        try:
            with open(self.keychain_path, 'rb') as f:
                keychain_data = plistlib.load(f)
        except FileNotFoundError:
            raise FileNotFoundError(f"Keychain file not found: {self.keychain_path}")
        except Exception as e:
            raise Exception(f"Failed to load keychain plist: {str(e)}")
        
        # Extract class keys
        self._extract_class_keys(keychain_data)
        print(f"  Found {len(self.class_keys)} class keys")
        
        # Get keychain entries
        entries_list = keychain_data.get('keychainEntries', [])
        print(f"  Found {len(entries_list)} keychain entries")
        
        # Process each entry
        processed_count = 0
        for entry_data in entries_list:
            try:
                entry = KeychainEntry(entry_data)
                self.entries.append(entry)
                
                # Try to process this entry
                if self._process_entry(entry):
                    processed_count += 1
                    
                    # If we successfully extracted a key, store it
                    if entry.service_name and entry.actual_key:
                        self.extracted_keys[entry.service_name] = entry.actual_key
                        print(f"  ✓ Extracted key for service: {entry.service_name}")
                        
            except Exception as e:
                # Continue processing other entries if one fails
                continue
        
        print(f"  Successfully processed {processed_count} entries")
        return self.extracted_keys
    
    def _extract_class_keys(self, keychain_data: dict) -> None:
        """
        Extract class keys from the keychain data.
        
        Args:
            keychain_data: The loaded plist data
        """
        class_keys_dict = keychain_data.get('classKeyIdxToUnwrappedMetadataClassKey', {})
        
        for idx_str, key_bytes in class_keys_dict.items():
            try:
                # Convert string index to integer
                idx = int(idx_str)
                self.class_keys[idx] = key_bytes
            except (ValueError, Exception) as e:
                print(f"Warning: Failed to load class key {idx_str}: {str(e)}")
    
    def _process_entry(self, entry: KeychainEntry) -> bool:
        """
        Process a keychain entry through all decryption stages.
        
        Args:
            entry: The KeychainEntry to process
            
        Returns:
            True if processing was successful, False otherwise
        """
        try:
            # Stage 1: Decrypt wrapped key to get metadata key
            if entry.metadata_wrapped_key and entry.class_key_idx is not None:
                entry.metadata_key = self._decrypt_wrapped_key(
                    entry.metadata_wrapped_key,
                    entry.class_key_idx
                )
            
            if not entry.metadata_key:
                return False
            
            # Stage 2: Decrypt metadata to get service information
            if entry.metadata_key and entry.metadata_ciphertext:
                entry.metadata_content, entry.metadata_plaintext = self._decrypt_metadata(
                    entry.metadata_ciphertext,
                    entry.metadata_key
                )
            
            if not entry.metadata_content:
                return False
            
            # Extract service name from metadata
            entry.service_name = self._get_service_name(entry.metadata_content)
            
            # Only continue if this is a service we care about
            # Services: BeaconStore, Observations, and other searchpartyd-related services
            # iOS 16+ adds additional encrypted databases with their own keys:
            #   - CloudStorage.db uses CloudStorage key
            #   - CloudStorage_CKRecordCache.db uses CloudKitCache key  
            #   - ItemSharingKeys.db uses KeyDatabase key
            #   - StandaloneBeacon.db uses StandAloneBeacon key
            target_services = ['beaconstore', 'observations', 'keydatabase', 'cloudstorage', 
                              'cloudkitcache', 'itemsharingkeys', 'standalonbeacon', 'standalonebeacon', 'beacon']
            if not entry.service_name:
                return False
            
            service_lower = entry.service_name.lower()
            if not any(target in service_lower for target in target_services):
                return False
            
            # Stage 3: Try to extract the key from data (iOS 17.5+)
            if entry.data_unwrapped_key and entry.data_ciphertext:
                entry.actual_key = self._decrypt_data(
                    entry.data_ciphertext,
                    entry.data_unwrapped_key
                )
            
            # If data decryption didn't yield a key, try metadata (iOS < 17.5)
            if not entry.actual_key and entry.metadata_plaintext:
                entry.actual_key = self._extract_key_from_metadata(entry.metadata_plaintext)
            
            return entry.actual_key is not None
            
        except Exception:
            return False
    
    def _decrypt_wrapped_key(self, wrapped_key: bytes, class_key_idx: int) -> Optional[bytes]:
        """
        Decrypt the wrapped key using the appropriate class key.
        
        Args:
            wrapped_key: The wrapped key bytes (contains NSKeyedArchiver bplist)
            class_key_idx: Index of the class key to use
            
        Returns:
            The 32-byte metadata key, or None if decryption fails
        """
        try:
            # Parse the wrapped key as a bplist (NSKeyedArchiver format)
            nested_plist = plistlib.loads(wrapped_key)
            
            # Extract from NSKeyedArchiver format
            # The root object contains UIDs that point to the actual data
            objects = nested_plist.get('$objects', [])
            
            if len(objects) < 2:
                return None
            
            # Get the root dictionary (usually at index 1)
            root_dict = objects[1]
            if not isinstance(root_dict, dict):
                return None
            
            # Follow the UIDs to get the actual values
            try:
                ct_uid = root_dict['SFCiphertext'].data
                auth_uid = root_dict['SFAuthenticationCode'].data
                iv_uid = root_dict['SFInitializationVector'].data
                
                ciphertext = objects[ct_uid]
                auth_tag = objects[auth_uid]
                iv = objects[iv_uid]
            except (KeyError, AttributeError, IndexError):
                return None
            
            if not all([isinstance(x, bytes) for x in [iv, auth_tag, ciphertext]]):
                return None
            
            # Get the class key
            class_key = self.class_keys.get(class_key_idx)
            if not class_key:
                return None
            
            # Decrypt using AES-GCM
            aesgcm = AESGCM(class_key)
            metadata_key = aesgcm.decrypt(iv, ciphertext + auth_tag, None)
            
            return metadata_key
            
        except Exception:
            return None
    
    def _decrypt_metadata(self, metadata_ciphertext: bytes, metadata_key: bytes) -> tuple:
        """
        Decrypt the metadata ciphertext using the metadata key.
        
        Args:
            metadata_ciphertext: The encrypted metadata (contains NSKeyedArchiver bplist)
            metadata_key: The 32-byte metadata key
            
        Returns:
            Tuple of (metadata_dict, plaintext_bytes) or (None, None) if decryption fails
        """
        try:
            # Parse the ciphertext as a bplist (NSKeyedArchiver format)
            nested_plist = plistlib.loads(metadata_ciphertext)
            
            # Extract from NSKeyedArchiver format
            objects = nested_plist.get('$objects', [])
            
            if len(objects) < 2:
                return None, None
            
            # Get the root dictionary and follow UIDs
            root_dict = objects[1]
            if not isinstance(root_dict, dict):
                return None, None
            
            try:
                ct_uid = root_dict['SFCiphertext'].data
                auth_uid = root_dict['SFAuthenticationCode'].data
                iv_uid = root_dict['SFInitializationVector'].data
                
                ciphertext = objects[ct_uid]
                auth_tag = objects[auth_uid]
                iv = objects[iv_uid]
            except (KeyError, AttributeError, IndexError):
                return None, None
            
            if not all([isinstance(x, bytes) for x in [iv, auth_tag, ciphertext]]):
                return None, None
            
            # Decrypt using AES-GCM
            aesgcm = AESGCM(metadata_key)
            metadata_plaintext = aesgcm.decrypt(iv, ciphertext + auth_tag, None)
            
            # Try to parse as plist first
            try:
                metadata_dict = plistlib.loads(metadata_plaintext)
                return metadata_dict, metadata_plaintext
            except:
                # If not a plist, parse as text/ASN.1
                metadata_dict = self._parse_metadata_plaintext(metadata_plaintext)
                return metadata_dict, metadata_plaintext
            
        except Exception:
            return None, None
    
    def _decrypt_data(self, data_ciphertext: bytes, unwrapped_key: bytes) -> Optional[bytes]:
        """
        Decrypt the data ciphertext using the unwrapped key (iOS 17.5+).
        
        Args:
            data_ciphertext: The encrypted data (contains NSKeyedArchiver bplist)
            unwrapped_key: The unwrapped key (32 bytes)
            
        Returns:
            The 32-byte encryption key, or None if not found
        """
        try:
            # Parse the ciphertext as a bplist (NSKeyedArchiver format)
            nested_plist = plistlib.loads(data_ciphertext)
            
            # Extract from NSKeyedArchiver format
            objects = nested_plist.get('$objects', [])
            
            if len(objects) < 2:
                return None
            
            # Get the root dictionary and follow UIDs
            root_dict = objects[1]
            if not isinstance(root_dict, dict):
                return None
            
            try:
                ct_uid = root_dict['SFCiphertext'].data
                auth_uid = root_dict['SFAuthenticationCode'].data
                iv_uid = root_dict['SFInitializationVector'].data
                
                ciphertext = objects[ct_uid]
                auth_tag = objects[auth_uid]
                iv = objects[iv_uid]
            except (KeyError, AttributeError, IndexError):
                return None
            
            if not all([isinstance(x, bytes) for x in [iv, auth_tag, ciphertext]]):
                return None
            
            # Decrypt using AES-GCM
            aesgcm = AESGCM(unwrapped_key)
            plaintext = aesgcm.decrypt(iv, ciphertext + auth_tag, None)
            
            # Search for the key pattern: "Data" followed by 0x04 0x20, then 32 bytes
            pattern = b'Data\x04\x20'
            
            pattern_index = plaintext.find(pattern)
            
            if pattern_index == -1:
                return None
            
            # The key starts immediately after the pattern
            key_start = pattern_index + len(pattern)
            
            # Extract 32 bytes
            if len(plaintext) >= key_start + 32:
                actual_key = plaintext[key_start:key_start + 32]
                return actual_key
            
            return None
            
        except Exception:
            return None
    
    def _extract_key_from_metadata(self, metadata_plaintext: bytes) -> Optional[bytes]:
        """
        Extract the key directly from metadata plaintext (iOS < 17.5).
        In older iOS versions, the key is stored in the metadata instead of data.
        
        Args:
            metadata_plaintext: The decrypted metadata plaintext bytes
            
        Returns:
            The 32-byte encryption key, or None if not found
        """
        try:
            # Search for the pattern: 'gena' followed by 0x04 0x20, then 32 bytes
            pattern = b'gena\x04\x20'
            
            pattern_index = metadata_plaintext.find(pattern)
            
            if pattern_index == -1:
                return None
            
            # The key starts immediately after the pattern
            key_start = pattern_index + len(pattern)
            
            # Extract 32 bytes
            if len(metadata_plaintext) >= key_start + 32:
                actual_key = metadata_plaintext[key_start:key_start + 32]
                return actual_key
            
            return None
                
        except Exception:
            return None
    
    def _parse_metadata_plaintext(self, plaintext: bytes) -> dict:
        """
        Parse metadata plaintext (could be ASN.1 or plist format).
        
        Args:
            plaintext: Raw decrypted metadata
            
        Returns:
            Dictionary with parsed metadata fields
        """
        metadata = {}
        
        # Try to extract text fields
        try:
            # Look for common patterns in the data
            text = plaintext.decode('utf-8', errors='ignore')
            
            # Look for svce field (service name)
            if 'svce' in text:
                # Find the svce marker
                svce_idx = text.find('svce')
                # Extract the section after svce
                section = text[svce_idx+4:svce_idx+100]
                
                # Split by null bytes and control characters
                parts = section.replace('\x00', '|').replace('\x0c', '|').split('|')
                for part in parts:
                    # Look for words that look like service names
                    # Remove non-printable characters
                    clean = ''.join(c for c in part if c.isprintable() and c not in '\x00\x0c')
                    # Strip trailing digits and special characters
                    clean = clean.rstrip('0123456789')
                    if len(clean) > 3 and len(clean) < 50 and not clean.isdigit():
                        metadata['svce'] = clean
                        break
            
            # Also look for acct field (account name)
            if 'acct' in text:
                acct_idx = text.find('acct')
                section = text[acct_idx+4:acct_idx+100]
                parts = section.replace('\x00', '|').replace('\x0c', '|').split('|')
                for part in parts:
                    clean = ''.join(c for c in part if c.isprintable() and c not in '\x00\x0c')
                    if len(clean) > 3 and len(clean) < 50 and not clean.isdigit():
                        metadata['acct'] = clean
                        break
            
        except Exception:
            pass
        
        return metadata
    
    def _get_service_name(self, metadata_dict: dict) -> Optional[str]:
        """
        Extract the service name from metadata dictionary.
        
        Args:
            metadata_dict: Parsed metadata dictionary
            
        Returns:
            Service name string, or None if not found
        """
        # Try different possible keys for service name
        for key in ['svce', 'service', 'svc', 'serviceName']:
            if key in metadata_dict:
                value = metadata_dict[key]
                if isinstance(value, bytes):
                    return value.decode('utf-8', errors='ignore')
                return str(value)
        
        return None
    
    def get_beacon_store_key(self) -> Optional[bytes]:
        """
        Get the BeaconStore key specifically.
        
        Returns:
            The 32-byte BeaconStore key, or None if not found
        """
        return self.extracted_keys.get('BeaconStore')
    
    def get_observations_key(self) -> Optional[bytes]:
        """
        Get the Observations key for Observations.db decryption.
        
        Returns:
            The 32-byte Observations key, or None if not found
        """
        return self.extracted_keys.get('Observations')
    
    def get_cloud_storage_key(self) -> Optional[bytes]:
        """
        Get the CloudStorage key for CloudStorage.db decryption (iOS 16+).
        
        Returns:
            The 32-byte CloudStorage key, or None if not found
        """
        return self.extracted_keys.get('CloudStorage')
    
    def get_cloudkit_cache_key(self) -> Optional[bytes]:
        """
        Get the CloudKitCache key for CloudStorage_CKRecordCache.db decryption (iOS 16+).
        
        Returns:
            The 32-byte CloudKitCache key, or None if not found
        """
        return self.extracted_keys.get('CloudKitCache')
    
    def get_key_database_key(self) -> Optional[bytes]:
        """
        Get the KeyDatabase key for ItemSharingKeys.db decryption (iOS 16+).
        
        Returns:
            The 32-byte KeyDatabase key, or None if not found
        """
        return self.extracted_keys.get('KeyDatabase')
    
    def get_standalone_beacon_key(self) -> Optional[bytes]:
        """
        Get the StandAloneBeacon key for StandaloneBeacon.db decryption (iOS 16+).
        
        Returns:
            The 32-byte StandAloneBeacon key, or None if not found
        """
        # Try both spellings that might appear in keychain
        key = self.extracted_keys.get('StandAloneBeacon')
        if not key:
            key = self.extracted_keys.get('StandaloneBeacon')
        return key
    
    def get_key_by_service(self, service_name: str) -> Optional[bytes]:
        """
        Get a key by its service name.
        
        Args:
            service_name: Name of the service (e.g., 'BeaconStore')
            
        Returns:
            The key as bytes, or None if not found
        """
        return self.extracted_keys.get(service_name)
    
    def list_available_keys(self) -> List[str]:
        """
        Get a list of all available service names.
        
        Returns:
            List of service name strings
        """
        return list(self.extracted_keys.keys())


# Example usage
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        extractor = iOSKeychainExtractor(sys.argv[1])
        
        print("Extracting keys from keychain...")
        keys = extractor.parse()
        
        print(f"\nFound {len(keys)} keys:")
        for service_name in extractor.list_available_keys():
            key = extractor.get_key_by_service(service_name)
            print(f"  - {service_name}: {key.hex()[:32]}... ({len(key)} bytes)")
        
        beacon_key = extractor.get_beacon_store_key()
        if beacon_key:
            print(f"\n✓ BeaconStore key found!")
            print(f"  Key (hex): {beacon_key.hex()}")
        else:
            print(f"\n✗ BeaconStore key not found")
            print(f"  Available services: {', '.join(extractor.list_available_keys())}")
    else:
        print("Usage: python ios_keychain_extractor.py <path_to_keychain.plist>")
