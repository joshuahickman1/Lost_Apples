#!/usr/bin/env python3
"""
Unified Cross-Platform ZIP Handler for searchpartyd_Parser

This handler works for ALL scenarios:
1. UFED extractions (with extra/KeychainDump/ and filesystem/ structure)
2. Graykey extractions (with Library/com.apple.icloud.searchpartyd/ structure)
3. Local storage (Mac or Windows machines)
4. Network storage locations

Key features:
- Automatic detection of zip type (UFED vs Graykey)
- Cross-platform path handling (Mac/Windows/network)
- Robust searchpartyd folder detection
- Integrated keychain extraction for UFED
- Proper temporary file management
"""

import zipfile
import tempfile
import shutil
import re
from pathlib import Path, PurePosixPath
from typing import Optional, Tuple, List


class UnifiedZipHandler:
    """
    Unified handler for both UFED and Graykey iOS extraction zip files.
    Works on Mac, Windows, and network storage locations.
    """
    
    def __init__(self, zip_path):
        """
        Initialize the zip handler.
        
        Args:
            zip_path: Path to zip file (string or Path object)
            
        Raises:
            FileNotFoundError: If zip file doesn't exist
            ValueError: If file is not a valid zip file
        """
        # Convert to Path object (works with strings, Paths, and network paths)
        self.zip_path = Path(zip_path).resolve()
        
        if not self.zip_path.exists():
            raise FileNotFoundError(f"Zip file not found: {zip_path}")
        
        if not zipfile.is_zipfile(self.zip_path):
            raise ValueError(f"Not a valid zip file: {zip_path}")
        
        self.temp_dir = None
        self.searchpartyd_path = None
        self.findmylocated_path = None  # Path to com.apple.findmy.findmylocated
        self.keychain_path = None
        self.zip_type = None  # Will be 'UFED' or 'Graykey'
        
    def detect_zip_type(self) -> str:
        """
        Detect whether this is a UFED or Graykey extraction.
        
        UFED zips have SPECIFIC structure at ROOT level:
        - extra/ folder (at root)
        - KeychainDump/ folder (inside extra/)
        - filesystem/ or filesystem1/, filesystem2/ etc. (at root)
        
        Graykey zips have:
        - Library/com.apple.icloud.searchpartyd/ structure
        - No extra/ folder at root
        - No KeychainDump/ folder
        
        Returns:
            'UFED' if UFED structure detected, 'Graykey' otherwise
        """
        with zipfile.ZipFile(self.zip_path, 'r') as zf:
            all_paths = zf.namelist()
            
            # Convert all paths to lowercase for case-insensitive matching
            lowercase_paths = [p.lower() for p in all_paths]
            
            # CRITICAL: Check for UFED indicators at ROOT level only
            # UFED has "extra/" as a TOP-LEVEL folder
            has_extra_root = any(path.startswith('extra/') for path in lowercase_paths)
            
            # UFED has "KeychainDump/" inside extra/
            has_keychain_dump = any('extra/keychaindump/' in path for path in lowercase_paths)
            
            # UFED has "filesystem/" or "filesystem1/" etc. as TOP-LEVEL folders
            # Match ONLY at start of path: filesystem/, filesystem1/, filesystem2/, etc.
            has_filesystem_root = any(
                re.match(r'^filesystem\d*/', path) for path in lowercase_paths
            )
            
            # Must have at least 2 of the 3 UFED indicators
            ufed_indicators = sum([has_extra_root, has_keychain_dump, has_filesystem_root])
            
            if ufed_indicators >= 2:
                self.zip_type = 'UFED'
                return 'UFED'
            else:
                self.zip_type = 'Graykey'
                return 'Graykey'
    
    def _find_filesystem_folders_ufed(self) -> List[str]:
        """
        Find all filesystem folders in UFED zip file.
        
        Returns:
            List of filesystem folder names at root level
        """
        with zipfile.ZipFile(self.zip_path, 'r') as zf:
            all_files = zf.namelist()
            
            filesystem_folders = set()
            for name in all_files:
                # Use PurePosixPath since zip files always use forward slashes
                posix_path = PurePosixPath(name.lower())
                parts = posix_path.parts
                
                # Check if first part matches filesystem pattern
                if parts and re.match(r'^filesystem\d*$', parts[0]):
                    filesystem_folders.add(parts[0])
            
            return sorted(list(filesystem_folders))
    
    def _find_searchpartyd_in_ufed(self) -> Optional[str]:
        """
        Find searchpartyd folder within UFED filesystem folders.
        
        Returns:
            Internal zip path to searchpartyd folder, or None
        """
        filesystem_folders = self._find_filesystem_folders_ufed()
        
        if not filesystem_folders:
            return None
        
        with zipfile.ZipFile(self.zip_path, 'r') as zf:
            all_paths = zf.namelist()
            
            # Search each filesystem folder for searchpartyd
            for fs_folder in filesystem_folders:
                for path in all_paths:
                    # Skip CloudKit cache paths
                    if 'Caches' in path or 'CloudKit' in path:
                        continue
                    
                    # Check if path starts with this filesystem folder
                    if path.lower().startswith(fs_folder.lower() + '/'):
                        # Check for Library/com.apple.icloud.searchpartyd pattern
                        if '/library/com.apple.icloud.searchpartyd/' in path.lower():
                            # Extract the path up to and including searchpartyd
                            parts = PurePosixPath(path).parts
                            
                            for i, part in enumerate(parts):
                                if part.lower() == 'library':
                                    if i + 1 < len(parts) and parts[i + 1].lower() == 'com.apple.icloud.searchpartyd':
                                        # Return path including searchpartyd
                                        return '/'.join(parts[:i+2])
            
            return None
    
    def _find_searchpartyd_graykey(self) -> Optional[str]:
        """
        Find searchpartyd folder in Graykey zip (Library as direct parent).
        
        Returns:
            Internal zip path to searchpartyd folder, or None
        """
        with zipfile.ZipFile(self.zip_path, 'r') as zf:
            all_paths = zf.namelist()
            
            # Look for com.apple.icloud.searchpartyd folders
            searchpartyd_folders = [
                path for path in all_paths 
                if 'com.apple.icloud.searchpartyd' in path.lower()
            ]
            
            # Filter for ones with Library as DIRECT parent (not CloudKit cache)
            for folder_path in searchpartyd_folders:
                parts = PurePosixPath(folder_path).parts
                
                # Skip CloudKit cache paths
                if any(p.lower() in ['caches', 'cloudkit'] for p in parts):
                    continue
                
                # Look for Library in the path hierarchy
                for i, part in enumerate(parts):
                    if part.lower() == 'library':
                        # Check if com.apple.icloud.searchpartyd comes IMMEDIATELY after Library
                        if i + 1 < len(parts) and parts[i + 1].lower() == 'com.apple.icloud.searchpartyd':
                            # Found it! Return the path up to and including searchpartyd
                            searchpartyd_index = i + 2
                            path_parts = parts[:searchpartyd_index]
                            
                            # If first part is '/', join with '/' to maintain absolute path
                            if path_parts[0] == '/':
                                return '/' + '/'.join(path_parts[1:])
                            else:
                                return '/'.join(path_parts)
            
            return None
    
    def _find_findmylocated_in_ufed(self) -> Optional[str]:
        """
        Find findmylocated folder within UFED filesystem folders.
        This folder contains iOS 17+ FindMy device tracking databases.
        
        Returns:
            Internal zip path to findmylocated folder, or None
        """
        filesystem_folders = self._find_filesystem_folders_ufed()
        
        if not filesystem_folders:
            return None
        
        with zipfile.ZipFile(self.zip_path, 'r') as zf:
            all_paths = zf.namelist()
            
            # Search each filesystem folder for findmylocated
            for fs_folder in filesystem_folders:
                for path in all_paths:
                    # Skip CloudKit cache paths
                    if 'Caches' in path or 'CloudKit' in path:
                        continue
                    
                    # Check if path starts with this filesystem folder
                    if path.lower().startswith(fs_folder.lower() + '/'):
                        # Check for Library/com.apple.findmy.findmylocated pattern
                        if '/library/com.apple.findmy.findmylocated/' in path.lower():
                            # Extract the path up to and including findmylocated
                            parts = PurePosixPath(path).parts
                            
                            for i, part in enumerate(parts):
                                if part.lower() == 'library':
                                    if i + 1 < len(parts) and parts[i + 1].lower() == 'com.apple.findmy.findmylocated':
                                        # Return path including findmylocated
                                        return '/'.join(parts[:i+2])
            
            return None
    
    def _find_findmylocated_graykey(self) -> Optional[str]:
        """
        Find findmylocated folder in Graykey zip (Library as direct parent).
        This folder contains iOS 17+ FindMy device tracking databases.
        
        Returns:
            Internal zip path to findmylocated folder, or None
        """
        with zipfile.ZipFile(self.zip_path, 'r') as zf:
            all_paths = zf.namelist()
            
            # Look for com.apple.findmy.findmylocated folders
            findmylocated_folders = [
                path for path in all_paths 
                if 'com.apple.findmy.findmylocated' in path.lower()
            ]
            
            # Filter for ones with Library as DIRECT parent (not CloudKit cache)
            for folder_path in findmylocated_folders:
                parts = PurePosixPath(folder_path).parts
                
                # Skip CloudKit cache paths
                if any(p.lower() in ['caches', 'cloudkit'] for p in parts):
                    continue
                
                # Look for Library in the path hierarchy
                for i, part in enumerate(parts):
                    if part.lower() == 'library':
                        # Check if com.apple.findmy.findmylocated comes IMMEDIATELY after Library
                        if i + 1 < len(parts) and parts[i + 1].lower() == 'com.apple.findmy.findmylocated':
                            # Found it! Return the path up to and including findmylocated
                            findmylocated_index = i + 2
                            path_parts = parts[:findmylocated_index]
                            
                            # If first part is '/', join with '/' to maintain absolute path
                            if path_parts[0] == '/':
                                return '/' + '/'.join(path_parts[1:])
                            else:
                                return '/'.join(path_parts)
            
            return None
    
    def _find_keychain_ufed(self) -> Optional[str]:
        """
        Find keychain file in UFED zip (in extra/KeychainDump/).
        
        Enhanced to handle multiple keychain filename patterns:
        - keychain (no extension)
        - keychain.plist
        - backup_keychain_v2.plist
        - any file with 'keychain' in the name
        
        Returns:
            Internal zip path to keychain file, or None
        """
        with zipfile.ZipFile(self.zip_path, 'r') as zf:
            all_paths = zf.namelist()
            
            # Look for keychain files in extra/KeychainDump/
            keychain_candidates = []
            
            for path in all_paths:
                # Check if path is in KeychainDump directory (case-insensitive)
                path_lower = path.lower()
                
                # Must be in extra/keychaindump/ path
                if 'extra/keychaindump/' in path_lower:
                    # Must be a file (not a directory)
                    if not path.endswith('/'):
                        # Get just the filename
                        filename = path.split('/')[-1].lower()
                        
                        # Check if filename contains 'keychain'
                        if 'keychain' in filename:
                            keychain_candidates.append(path)
            
            if not keychain_candidates:
                return None
            
            # Prioritize files by preference:
            # 1. Files ending in .plist (most common modern format)
            # 2. Files named exactly 'keychain'
            # 3. Any other file with 'keychain' in the name
            
            plist_files = [p for p in keychain_candidates if p.lower().endswith('.plist')]
            if plist_files:
                # If multiple .plist files, prefer ones with 'backup' in name
                plist_files.sort(key=lambda x: (
                    'backup' not in x.lower(),  # backup_keychain_v2.plist first
                    len(x)  # Then shortest path
                ))
                return plist_files[0]
            
            # Look for exact 'keychain' filename (no extension)
            exact_match = [p for p in keychain_candidates 
                          if p.split('/')[-1].lower() == 'keychain']
            if exact_match:
                return exact_match[0]
            
            # Fall back to first candidate found
            if keychain_candidates:
                keychain_candidates.sort(key=len)  # Prefer shortest path
                return keychain_candidates[0]
            
            return None
    
    def extract_all(self) -> Tuple[Optional[str], Optional[str]]:
        """
        Extract searchpartyd folder, findmylocated folder, and keychain to temporary location.
        
        Returns:
            Tuple of (searchpartyd_path, keychain_path)
            Both are None if searchpartyd not found, keychain_path is None for Graykey
            
        Note:
            findmylocated_path is stored in self.findmylocated_path after extraction
            Use get_findmylocated_path() to retrieve it
        """
        # Detect zip type if not already done
        if not self.zip_type:
            self.detect_zip_type()
        
        # Find folders based on zip type
        if self.zip_type == 'UFED':
            internal_searchpartyd = self._find_searchpartyd_in_ufed()
            internal_findmylocated = self._find_findmylocated_in_ufed()
            internal_keychain = self._find_keychain_ufed()
        else:  # Graykey
            internal_searchpartyd = self._find_searchpartyd_graykey()
            internal_findmylocated = self._find_findmylocated_graykey()
            internal_keychain = None
        
        if not internal_searchpartyd:
            return None, None
        
        # Create temporary directory in current working directory
        # This works for Mac, Windows, and network locations
        cwd = Path.cwd()
        temp_base = cwd / '.searchpartyd_temp'
        temp_base.mkdir(exist_ok=True)
        self.temp_dir = Path(tempfile.mkdtemp(prefix='extraction_', dir=str(temp_base)))
        
        # Extract folders
        with zipfile.ZipFile(self.zip_path, 'r') as zf:
            # Get all files in or under the searchpartyd folder
            files_to_extract = [
                name for name in zf.namelist()
                if name.startswith(internal_searchpartyd)
            ]
            
            # Also get files for findmylocated if it exists
            if internal_findmylocated:
                findmylocated_files = [
                    name for name in zf.namelist()
                    if name.startswith(internal_findmylocated)
                ]
                files_to_extract.extend(findmylocated_files)
            
            # Extract all relevant files
            for file_path in files_to_extract:
                zf.extract(file_path, self.temp_dir)
            
            # Extract keychain if it exists (UFED only)
            if internal_keychain:
                zf.extract(internal_keychain, self.temp_dir)
        
        # Build platform-specific path to searchpartyd
        internal_posix = PurePosixPath(internal_searchpartyd)
        parts = internal_posix.parts
        
        # Remove leading slash if present
        if parts and parts[0] == '/':
            parts = parts[1:]
        
        # Build platform-specific path
        self.searchpartyd_path = self.temp_dir
        for part in parts:
            self.searchpartyd_path = self.searchpartyd_path / part
        
        # Verify searchpartyd path exists
        if not self.searchpartyd_path.exists():
            print(f"Warning: Extracted searchpartyd path does not exist: {self.searchpartyd_path}")
            return None, None
        
        # Build findmylocated path if it exists
        if internal_findmylocated:
            findmylocated_posix = PurePosixPath(internal_findmylocated)
            findmylocated_parts = findmylocated_posix.parts
            
            # Remove leading slash if present
            if findmylocated_parts and findmylocated_parts[0] == '/':
                findmylocated_parts = findmylocated_parts[1:]
            
            # Build platform-specific path
            self.findmylocated_path = self.temp_dir
            for part in findmylocated_parts:
                self.findmylocated_path = self.findmylocated_path / part
            
            # Verify findmylocated exists
            if not self.findmylocated_path.exists():
                self.findmylocated_path = None
        
        # Build keychain path if it exists
        if internal_keychain:
            keychain_posix = PurePosixPath(internal_keychain)
            keychain_parts = keychain_posix.parts
            
            # Remove leading slash if present
            if keychain_parts and keychain_parts[0] == '/':
                keychain_parts = keychain_parts[1:]
            
            # Build platform-specific path
            self.keychain_path = self.temp_dir
            for part in keychain_parts:
                self.keychain_path = self.keychain_path / part
            
            # Verify keychain exists
            if not self.keychain_path.exists():
                self.keychain_path = None
        
        return (
            str(self.searchpartyd_path.resolve()) if self.searchpartyd_path else None,
            str(self.keychain_path.resolve()) if self.keychain_path else None
        )
    
    def get_findmylocated_path(self) -> Optional[str]:
        """
        Get the extracted findmylocated folder path.
        
        This folder contains iOS 17+ FindMy device tracking databases:
        - LocalStorage.db
        - CloudStorage.db
        - CloudStorage_CKRecordCache.db
        
        Returns:
            Path to extracted findmylocated folder, or None if not found
        """
        if self.findmylocated_path and self.findmylocated_path.exists():
            return str(self.findmylocated_path.resolve())
        return None
    
    def get_info(self) -> dict:
        """
        Get information about the zip file without extracting.
        
        Returns:
            Dictionary with zip information:
            - zip_type: 'UFED' or 'Graykey'
            - has_searchpartyd: bool
            - has_findmylocated: bool (iOS 17+ folder)
            - has_keychain: bool (UFED only)
            - filesystem_folders: list (UFED only)
        """
        # Detect type if not already done
        if not self.zip_type:
            self.detect_zip_type()
        
        info = {
            'zip_type': self.zip_type,
            'has_searchpartyd': False,
            'has_findmylocated': False,
            'has_keychain': False,
            'filesystem_folders': []
        }
        
        if self.zip_type == 'UFED':
            info['filesystem_folders'] = self._find_filesystem_folders_ufed()
            info['has_searchpartyd'] = self._find_searchpartyd_in_ufed() is not None
            info['has_findmylocated'] = self._find_findmylocated_in_ufed() is not None
            info['has_keychain'] = self._find_keychain_ufed() is not None
        else:  # Graykey
            info['has_searchpartyd'] = self._find_searchpartyd_graykey() is not None
            info['has_findmylocated'] = self._find_findmylocated_graykey() is not None
        
        return info
    
    def cleanup(self):
        """Remove temporary directory and all extracted files."""
        if self.temp_dir and self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)
            self.temp_dir = None
            self.searchpartyd_path = None
            self.findmylocated_path = None
            self.keychain_path = None
            
            # Clean up temp base directory if empty
            try:
                temp_base = Path.cwd() / '.searchpartyd_temp'
                if temp_base.exists() and not any(temp_base.iterdir()):
                    temp_base.rmdir()
            except:
                pass  # Ignore cleanup errors
    
    def __enter__(self):
        """Context manager entry - extract files."""
        searchpartyd, keychain = self.extract_all()
        if not searchpartyd:
            raise ValueError(
                f"Could not find com.apple.icloud.searchpartyd folder in {self.zip_type} zip file: {self.zip_path}"
            )
        return searchpartyd, keychain
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - cleanup."""
        self.cleanup()
        return False


# Convenience functions
def is_zip_file(path: str) -> bool:
    """
    Check if the given path is a valid zip file.
    
    Args:
        path: Path to check
        
    Returns:
        True if path is a valid zip file, False otherwise
    """
    try:
        return zipfile.is_zipfile(path)
    except:
        return False


def detect_and_extract(zip_path: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Detect zip type and extract searchpartyd (and keychain if UFED).
    
    Args:
        zip_path: Path to the zip file
        
    Returns:
        Tuple of (searchpartyd_path, keychain_path, error_message)
        If successful, paths are set and error_message is None
        If failed, paths are None and error_message contains the error
    """
    try:
        handler = UnifiedZipHandler(zip_path)
        
        # Get info first
        info = handler.get_info()
        print(f"Detected {info['zip_type']} extraction")
        
        # Extract
        searchpartyd_path, keychain_path = handler.extract_all()
        
        if not searchpartyd_path:
            return None, None, (
                f"Could not find com.apple.icloud.searchpartyd folder in {info['zip_type']} zip.\n\n"
                "Please verify the zip file is a complete iOS extraction."
            )
        
        return searchpartyd_path, keychain_path, None
        
    except Exception as e:
        return None, None, f"Error processing zip file:\n{str(e)}"


# Example usage
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python unified_zip_handler.py <path_to_zip_file>")
        sys.exit(1)
    
    zip_file = sys.argv[1]
    
    print(f"Analyzing zip file: {zip_file}")
    print()
    
    try:
        handler = UnifiedZipHandler(zip_file)
        
        # Get info without extracting
        info = handler.get_info()
        print(f"Zip Type: {info['zip_type']}")
        print(f"Has searchpartyd: {info['has_searchpartyd']}")
        print(f"Has keychain: {info['has_keychain']}")
        
        if info['filesystem_folders']:
            print(f"Filesystem folders: {', '.join(info['filesystem_folders'])}")
        
        print()
        
        if not info['has_searchpartyd']:
            print("✗ No searchpartyd folder found in this zip")
            sys.exit(1)
        
        # Extract
        print("Extracting...")
        searchpartyd_path, keychain_path = handler.extract_all()
        
        print(f"\n✓ Searchpartyd extracted to:")
        print(f"  {searchpartyd_path}")
        
        if keychain_path:
            print(f"\n✓ Keychain extracted to:")
            print(f"  {keychain_path}")
        
        # List contents
        path = Path(searchpartyd_path)
        subdirs = [d.name for d in path.iterdir() if d.is_dir()]
        
        print(f"\nSearchpartyd subdirectories:")
        for d in sorted(subdirs):
            print(f"  - {d}")
        
        print("\n✓ Extraction successful!")
        print("(Remember to call handler.cleanup() when done)")
        
    except Exception as e:
        print(f"✗ Error: {e}")
        sys.exit(1)
