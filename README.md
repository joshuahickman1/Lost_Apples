![](lost_apple_graphic.png)

# Lost Apples 1.0 🍎

**A tool for parsing iOS FindMy network and Bluetooth tracker data on iOS devices**

For more information see the blog The Binary Hick:

[Where the Wild Tags Are & Other AirTag Stories](https://thebinaryhick.blog/2024/09/02/where-the-wild-tags-are-other-airtag-stories/)

[Further Observations - More on iOS Search Party](https://thebinaryhick.blog/2025/08/19/further-observations-more-on-ios-search-party/)


---

## Features

- **Keychain Parsing**: Automatically extracts the BeaconStore and Observations encryption keys from iOS keychain files
- **Multi-Record Type Parsing**: Supports multiple different record types from the searchpartyd folder
- **Observations.db Decryption**: Decrypts the SQLite database containing device observations with locations
- **Direct Zip & Folder Processing**: Directly process commercial tool zip file extractions from Premium/Inseyets or Graykey, or process the com.apple.icloud.searchpartyd folder & associated keychain
- **Export Options**: Export results to CSV and KML formats for further analysis
- **Beacon Name Enrichment**: Links custom beacon names and emojis across related records
- **File Integrity**: Preserves original files while creating separate decrypted copies
- **Cross-Platform**: Works on macOS and Windows

---

## Supported Record Types

| Record Type | Description | Forensic Value |
|-------------|-------------|----------------|
| **WildModeAssociationRecord** | Unwanted tracker alerts | Evidence of stalking/tracking via rogue AirTags/Bluetooth trackers |
| **BeaconNamingRecord** | Custom tracker names and emojis | User-assigned names for their devices |
| **OwnedBeacons** | Device pairing information | FindMy-compatible devices owned by the iCloud account on the device |
| **SafeLocations** | Designated safe zones | Locations where tracking alerts are suppressed |
| **BeaconEstimatedLocation** | Beacon location history | Historical location data for tracked items |
| **SharedBeacons** | Beacons shared with the user | FindMy-compatible devices others have shared with iCloud account on the device |
| **OwnerSharingCircle** | Beacons shared BY the user | Who the user has shared their FindMy-compatible devices with |
| **OwnerPeerTrust** | Peer sharing relationships | People with whom beacons are shared |
| **Observations.db** | SQLite database | Locations of the iOS device when FindMy devices are observed |

---

## Requirements

- **Python**: Version 3.8 or higher
- **Operating System**: macOS or Windows
- **Source Data**: iOS device extraction from commercial forensic tools (UFED, Graykey, Cellebrite, etc.) or the individual com.apple.icloud.searchpartyd folder with accompanying keychain

### Python Dependencies

- `cryptography` - For AES-256-GCM decryption
- `Pillow` - For GUI logo display (optional but recommended)

---

## Quick Start

### Step 1: Download or Clone the Repository

```bash
cd /path/to/your/projects
git clone <repository-url> Lost_Apples
cd Lost_Apples
```

Or download and extract the ZIP file to your desired location.

### Step 2: Install Python Dependencies

Open Terminal (macOS) or Command Prompt (Windows) and run:

```bash
# Navigate to the project folder
cd /path/to/Lost_Apples

# Install required packages
pip install -r requirements.txt
```

This installs the `cryptography` and `Pillow` libraries.

**Note for beginners:** If you have multiple Python versions installed, you may need to use `pip3` instead of `pip`:

```bash
pip3 install -r requirements.txt
```

### Step 3: Launch the GUI

```bash
python lost_apples.py
```

---

## Usage

### GUI Mode

The graphical interface is the recommended way to use Lost Apples. It provides:

- Step-by-step workflow guidance
- Real-time logging with color-coded messages
- Automatic extraction format detection
- One-click extraction, parsing and export

#### Basic Workflow

1. **Launch the GUI**: Run `python lost_apples.py` (some Python installations may require `python3 lost_apples.py`)

2. **Select Input Files**:
   - **Option A - Zip File**: Click "Browse" next to "Full Extraction Zip" and select your extraction zip file
     - For Premium/Inseyets.UFED extractions, the keychain is automatically detected (no need to extract from the zip)
     - For Graykey extractions, the keychain should be provided in addition to the zip file
   - **Option B - Individual Files**: 
     - Select the keychain plist file
     - Select the com.apple.icloud.searchpartyd folder containing the files you wish to process

3. **Start Analysis**: Process the data in the folder /private/var/mobile/Library/com.apple.icloud.searchpartyd folder

4. **Export Results**: Click the "Export Results..." to save results as CSV or KML files (some results have no KML option as they contain no location)

5. **Export Keys**: Click "Export Keys" to save the BeaconStore and Observations encryption keys to a text file in the working directory (requires analysis to be completed)

6. **Process Observations.db** (optional): Click "Query Observations..." to process the SQLite database

#### GUI Features

- **Log Window**: Shows detailed progress and any errors
- **Status Bar**: Displays current operation status

### Command Line Mode

Individual parsers can be run from the command line for scripted workflows or integration with other tools.

---

## Output Formats

### CSV Export

CSV files are created for each parsed record type with all available fields. Files are saved to a timestamped output folder.

Example CSV columns for WildMode records:
- UUID, Manufacturer, Model, Tracker_UUID
- First_Seen, Trigger_DateTime, and other status times
- MAC_Addresses, Location_Count
- Latitude, Longitude, Timestamp, Accuracy

### KML Export

KML files can be imported into Google Earth or other mapping applications to visualize location data.

- **Individual KML**: One file per record with all associated locations
- **Combined KML**: All locations from a record type in a single file (for information dervied from Observations.db)

### Decrypted File Export

Decrypted binary plist (bplist) files can be exported to the working directory when the option "Export decrypted bplist files" is selected.

Decrypted Observations.db and the associated write-ahead-log (-WAL) file are automatically exported to the working directory and preserved for further analysis if needed.

- **Observations.db queries**: CSV and KML exports are sent to the working directory when the queries are run


---

## iOS Version Compatibility

Lost Apples supports iOS extractions from:
- iOS 15.3.1 and later
- Tested on iOS 15.3.1, 16.x, 17.x, 18.x, and 26.x

Different iOS versions may store encryption keys in different locations within the keychain. The tool automatically detects the correct format.


