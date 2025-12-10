"""
Keychain Parser for searchpartyd
This module extracts encryption keys from the iOS keychain plist file.
Supports both UFED and Graykey extraction formats.

For Graykey format (iOS 17.5+):
- Keys are already decrypted and stored directly in the plist
- BeaconStore key: svce='BeaconStore', acct='BeaconStoreKey', key in v_Data
- Observations key: svce='Observations', acct='searchparty', key in v_Data

For older iOS (< 17.5) Graykey format:
- Keys may be in 'gena' field instead of 'v_Data'

For UFED format:
- Keys may require additional decryption steps
- Structure varies more significantly
"""

import plistlib
import base64
from typing import Dict, Optional, List


class KeychainParser:
    """Parser for extracting searchpartyd and findmylocated keys from keychain plist files."""
    
    # Target services we want to extract
    TARGET_SERVICES = {
        'BeaconStore': ['BeaconStore', 'BeaconStoreKey'],
        'Observations': ['Observations'],
        'KeyDatabase': ['KeyDatabase'],
        'CloudStorage': ['CloudStorage'],
        'StandaloneBeacon': ['StandaloneBeacon'],
        'SPBeaconKeyManager': ['SPBeaconKeyManager'],
        'LocalStorage': ['LocalStorage'],
        'CachedUnifiedBeacons': ['CachedUnifiedBeacons'],
        'CloudKitCache': ['CloudKitCache'],
    }
    
    # Access groups we want to process
    # searchpartyd: com.apple.icloud.searchpartyd folder databases
    # findmylocated: com.apple.findmy.findmylocated folder databases (iOS 17+)
    TARGET_ACCESS_GROUPS = ['searchpartyd', 'findmylocated']
    
    def __init__(self, keychain_path: str):
        """
        Initialize the keychain parser.
        
        Args:
            keychain_path: Path to the keychain plist file (e.g., backup_keychain_v2.plist or GK keychain)
        """
        self.keychain_path = keychain_path
        self.keys: Dict[str, bytes] = {}
        self.source_type: Optional[str] = None  # Will be 'UFED' or 'Graykey'
        
    def parse(self) -> Dict[str, bytes]:
        """
        Parse the keychain plist and extract searchpartyd-related keys.
        Auto-detects UFED or Graykey format.
        
        Returns:
            Dictionary mapping service names to their encryption keys
            
        Raises:
            FileNotFoundError: If keychain file doesn't exist
            Exception: If plist parsing fails
        """
        try:
            with open(self.keychain_path, 'rb') as f:
                keychain_data = plistlib.load(f)
        except FileNotFoundError:
            raise FileNotFoundError(f"Keychain file not found: {self.keychain_path}")
        except Exception as e:
            raise Exception(f"Failed to parse keychain plist: {str(e)}")
        
        # Detect format and parse accordingly
        if isinstance(keychain_data, list):
            # UFED format - list of entries
            self.source_type = 'UFED'
            for entry in keychain_data:
                self._extract_key_from_ufed_entry(entry)
        elif isinstance(keychain_data, dict):
            # Check if it's Graykey format (has 'genp', 'cert', 'inet', 'keys' sections)
            if 'genp' in keychain_data or 'cert' in keychain_data or 'inet' in keychain_data:
                self.source_type = 'Graykey'
                self._parse_graykey_format(keychain_data)
            # Check if it's the keychainEntries format (backup keychain v2)
            elif 'keychainEntries' in keychain_data:
                self.source_type = 'UFED'
                # This format requires complex decryption - handled by iOSKeychainExtractor
                # For basic parsing, we can't extract keys directly
                pass
            else:
                # Single UFED entry
                self.source_type = 'UFED'
                self._extract_key_from_ufed_entry(keychain_data)
            
        return self.keys
    
    def _parse_graykey_format(self, keychain_data: dict) -> None:
        """
        Parse Graykey format keychain.
        Graykey exports have pre-decrypted keys in a simple format.
        
        Args:
            keychain_data: Dictionary with 'genp', 'cert', 'inet', 'keys' sections
        """
        # BeaconStore and Observations keys are in the 'genp' (generic password) section
        genp_section = keychain_data.get('genp', [])
        
        print(f"  Parsing {len(genp_section)} generic password entries...")
        
        for entry in genp_section:
            if isinstance(entry, dict):
                self._extract_key_from_graykey_entry(entry)
        
        # Log what we found
        if self.keys:
            print(f"  Found {len(self.keys)} searchpartyd-related keys")
    
    def _extract_key_from_graykey_entry(self, entry: dict) -> None:
        """
        Extract key from a Graykey keychain entry.
        
        Graykey format stores keys directly:
        - svce: Service name (BeaconStore, Observations, CloudStorage, etc.)
        - acct: Account name
        - agrp: Access group determines the folder:
            - com.apple.icloud.searchpartyd.* -> searchpartyd folder
            - com.apple.findmy.findmylocated -> findmylocated folder (iOS 17+)
        - v_Data: The actual key (iOS 17.5+)
        - gena: The actual key (older iOS)
        
        Args:
            entry: Dictionary containing Graykey keychain entry data
        """
        # Get entry fields
        svce = entry.get('svce', b'')
        agrp = entry.get('agrp', b'')
        acct = entry.get('acct', b'')
        
        # Convert bytes to strings
        if isinstance(svce, bytes):
            svce = svce.decode('utf-8', errors='ignore')
        if isinstance(agrp, bytes):
            agrp = agrp.decode('utf-8', errors='ignore')
        if isinstance(acct, bytes):
            acct = acct.decode('utf-8', errors='ignore')
        
        # Only process entries from our target access groups (searchpartyd or findmylocated)
        agrp_lower = agrp.lower()
        is_searchpartyd = 'searchpartyd' in agrp_lower
        is_findmylocated = 'findmylocated' in agrp_lower
        
        if not is_searchpartyd and not is_findmylocated:
            return
        
        # Get the key data
        key_data = None
        
        # iOS 17.5+ format - key is in 'v_Data' field
        v_data = entry.get('v_Data')
        if v_data is not None:
            if isinstance(v_data, bytes) and len(v_data) == 32:
                key_data = v_data
        
        # Pre-iOS 17.5 format - key is in 'gena' field
        if key_data is None:
            gena = entry.get('gena')
            if gena is not None:
                if isinstance(gena, bytes) and len(gena) == 32:
                    key_data = gena
        
        if key_data is None:
            return
        
        # Store the key by service name
        # For services that exist in BOTH folders (CloudStorage, CloudKitCache),
        # we use folder-specific key names to distinguish them
        if svce:
            svce_lower = svce.lower()
            
            # Services that exist in both searchpartyd and findmylocated folders
            dual_folder_services = ['cloudstorage', 'cloudkitcache']
            
            if any(svc in svce_lower for svc in dual_folder_services):
                # Use folder-specific naming
                if is_findmylocated:
                    key_name = f"{svce}_findmylocated"
                else:
                    key_name = f"{svce}_searchpartyd"
                self.keys[key_name] = key_data
            else:
                # Standard service - store with original name
                self.keys[svce] = key_data
            
            # Also store with common aliases for frequently used keys
            if svce == 'BeaconStore':
                self.keys['BeaconStoreKey'] = key_data
            elif svce == 'Observations':
                self.keys['ObservationsKey'] = key_data
    
    def _extract_key_from_ufed_entry(self, entry: dict) -> None:
        """
        Extract key information from a UFED keychain entry.
        
        Args:
            entry: Dictionary containing UFED keychain entry data
        """
        # Check if this entry is related to searchpartyd
        access_group = entry.get('agrp', '')
        service = entry.get('svce', '')
        
        if isinstance(access_group, bytes):
            access_group = access_group.decode('utf-8', errors='ignore')
        if isinstance(service, bytes):
            service = service.decode('utf-8', errors='ignore')
        
        if 'searchpartyd' not in access_group and 'searchpartyd' not in service:
            return
        
        # Try to get the key - format varies by iOS version
        key_data = None
        
        # iOS 17.5+ format - key is stored under 'v_Data'
        v_data = entry.get('v_Data')
        if v_data is not None and isinstance(v_data, bytes) and len(v_data) == 32:
            key_data = v_data
        
        # Pre-iOS 17.5 format - check for GenericAttribute
        if key_data is None:
            gena = entry.get('gena')
            if gena is not None and isinstance(gena, bytes) and len(gena) == 32:
                key_data = gena
        
        if key_data and service:
            # Store the key with the service name as the identifier
            self.keys[service] = key_data
            
            # Also store with common aliases
            if service == 'BeaconStore':
                self.keys['BeaconStoreKey'] = key_data
            elif service == 'Observations':
                self.keys['ObservationsKey'] = key_data
    
    def get_beacon_store_key(self) -> Optional[bytes]:
        """
        Get the BeaconStore key specifically (used for most .record file decryption).
        
        Returns:
            The BeaconStore key as bytes, or None if not found
        """
        # Try multiple possible key names
        for key_name in ['BeaconStore', 'BeaconStoreKey']:
            key = self.keys.get(key_name)
            if key:
                return key
        return None
    
    def get_observations_key(self) -> Optional[bytes]:
        """
        Get the Observations key specifically (used for Observations.db decryption).
        
        Returns:
            The Observations key as bytes, or None if not found
        """
        # Try multiple possible key names
        for key_name in ['Observations', 'ObservationsKey']:
            key = self.keys.get(key_name)
            if key:
                return key
        return None
    
    def get_cloud_storage_key(self) -> Optional[bytes]:
        """
        Get the CloudStorage key for CloudStorage.db decryption (iOS 16+).
        
        Returns:
            The 32-byte CloudStorage key, or None if not found
        """
        return self.keys.get('CloudStorage')
    
    def get_cloudkit_cache_key(self) -> Optional[bytes]:
        """
        Get the CloudKitCache key for CloudStorage_CKRecordCache.db decryption (iOS 16+).
        
        Returns:
            The 32-byte CloudKitCache key, or None if not found
        """
        return self.keys.get('CloudKitCache')
    
    def get_key_database_key(self) -> Optional[bytes]:
        """
        Get the KeyDatabase key for ItemSharingKeys.db decryption (iOS 16+).
        
        Returns:
            The 32-byte KeyDatabase key, or None if not found
        """
        return self.keys.get('KeyDatabase')
    
    def get_standalone_beacon_key(self) -> Optional[bytes]:
        """
        Get the StandaloneBeacon key for StandaloneBeacon.db decryption (iOS 16+).
        
        Returns:
            The 32-byte StandaloneBeacon key, or None if not found
        """
        # Try both spellings that might appear in keychain
        key = self.keys.get('StandaloneBeacon')
        if not key:
            key = self.keys.get('StandAloneBeacon')
        return key
    
    # =========================================================================
    # FINDMYLOCATED FOLDER (com.apple.findmy.findmylocated) - iOS 17+ Keys
    # =========================================================================
    
    def get_local_storage_key(self) -> Optional[bytes]:
        """
        Get the LocalStorage key for LocalStorage.db decryption (iOS 17+).
        Located in: com.apple.findmy.findmylocated folder
        
        Returns:
            The 32-byte LocalStorage key, or None if not found
        """
        return self.keys.get('LocalStorage')
    
    def get_findmylocated_cloud_storage_key(self) -> Optional[bytes]:
        """
        Get the CloudStorage key for CloudStorage.db in the findmylocated folder.
        Located in: com.apple.findmy.findmylocated folder (iOS 17+)
        
        Returns:
            The 32-byte CloudStorage key for findmylocated, or None if not found
        """
        return self.keys.get('CloudStorage_findmylocated')
    
    def get_findmylocated_cloudkit_cache_key(self) -> Optional[bytes]:
        """
        Get the CloudKitCache key for CloudStorage_CKRecordCache.db in the findmylocated folder.
        Located in: com.apple.findmy.findmylocated folder (iOS 17+)
        
        Returns:
            The 32-byte CloudKitCache key for findmylocated, or None if not found
        """
        return self.keys.get('CloudKitCache_findmylocated')
    
    # =========================================================================
    # SEARCHPARTYD FOLDER (com.apple.icloud.searchpartyd) - Folder-Specific Keys  
    # =========================================================================
    
    def get_searchpartyd_cloud_storage_key(self) -> Optional[bytes]:
        """
        Get the CloudStorage key for CloudStorage.db in the searchpartyd folder.
        Located in: com.apple.icloud.searchpartyd folder
        
        Returns:
            The 32-byte CloudStorage key for searchpartyd, or None if not found
        """
        return self.keys.get('CloudStorage_searchpartyd')
    
    def get_searchpartyd_cloudkit_cache_key(self) -> Optional[bytes]:
        """
        Get the CloudKitCache key for CloudStorage_CKRecordCache.db in the searchpartyd folder.
        Located in: com.apple.icloud.searchpartyd folder
        
        Returns:
            The 32-byte CloudKitCache key for searchpartyd, or None if not found
        """
        return self.keys.get('CloudKitCache_searchpartyd')
    
    def get_key_by_service(self, service_name: str) -> Optional[bytes]:
        """
        Get a key by its service name.
        
        Args:
            service_name: Name of the service (e.g., 'BeaconStore', 'Observations')
            
        Returns:
            The key as bytes, or None if not found
        """
        return self.keys.get(service_name)
    
    def list_available_keys(self) -> List[str]:
        """
        Get a list of all available service names that have keys.
        
        Returns:
            List of service name strings
        """
        return list(self.keys.keys())
    
    def get_source_type(self) -> Optional[str]:
        """
        Get the detected keychain source type.
        
        Returns:
            'UFED', 'Graykey', or None if not yet parsed
        """
        return self.source_type


# Example usage
if __name__ == "__main__":
    # This is just for testing
    import sys
    
    if len(sys.argv) > 1:
        parser = KeychainParser(sys.argv[1])
        keys = parser.parse()
        
        print(f"\nDetected keychain format: {parser.get_source_type()}")
        print(f"Found {len(keys)} keys:")
        for service_name in parser.list_available_keys():
            key = parser.get_key_by_service(service_name)
            print(f"  - {service_name}: {len(key)} bytes")
        
        beacon_key = parser.get_beacon_store_key()
        if beacon_key:
            print(f"\n✓ BeaconStore key: {beacon_key.hex()}")
        else:
            print("\n✗ BeaconStore key not found")
        
        obs_key = parser.get_observations_key()
        if obs_key:
            print(f"✓ Observations key: {obs_key.hex()}")
        else:
            print("✗ Observations key not found")
    else:
        print("Usage: python keychain_parser.py <path_to_keychain.plist>")
