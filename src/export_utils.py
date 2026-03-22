"""
Export Utilities
This module provides CSV and KML export functionality for parsed iOS forensic data.
"""

import csv
import io
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime


class ExportUtils:
    """Utility class for exporting parsed data to various formats."""
    
    @staticmethod
    def export_to_csv(data: List[Dict[str, Any]], output_path: str, fieldnames: List[str] = None) -> bool:
        """
        Export data to a CSV file.
        
        Args:
            data: List of dictionaries containing the data to export
            output_path: Path where the CSV file should be saved
            fieldnames: Optional list of field names. If None, uses keys from first record
            
        Returns:
            True if export successful, False otherwise
        """
        if not data:
            print("No data to export")
            return False
        
        try:
            # If no fieldnames provided, use keys from first record
            if fieldnames is None:
                fieldnames = list(data[0].keys())
            
            # Create output directory if it doesn't exist
            output_dir = Path(output_path).parent
            output_dir.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                
                for row in data:
                    # Convert any datetime objects to strings
                    processed_row = {}
                    for key, value in row.items():
                        if isinstance(value, datetime):
                            processed_row[key] = value.isoformat()
                        elif isinstance(value, list):
                            # Convert lists to comma-separated strings
                            processed_row[key] = ', '.join(str(v) for v in value)
                        else:
                            processed_row[key] = value
                    
                    writer.writerow(processed_row)
            
            print(f"Successfully exported to CSV: {output_path}")
            return True
            
        except Exception as e:
            print(f"Error exporting to CSV: {str(e)}")
            return False
    
    @staticmethod
    def export_to_kml(data: List[Dict[str, Any]], output_path: str, name: str = "Locations") -> bool:
        """
        Export location data to a KML file for mapping applications.
        
        Args:
            data: List of dictionaries containing location data with 'latitude' and 'longitude'
            output_path: Path where the KML file should be saved
            name: Name for the KML document
            
        Returns:
            True if export successful, False otherwise
        """
        if not data:
            print("No data to export")
            return False
        
        try:
            # Create output directory if it doesn't exist
            output_dir = Path(output_path).parent
            output_dir.mkdir(parents=True, exist_ok=True)
            
            # Start KML document
            kml_content = ['<?xml version="1.0" encoding="UTF-8"?>']
            kml_content.append('<kml xmlns="http://www.opengis.net/kml/2.2">')
            kml_content.append('  <Document>')
            kml_content.append(f'    <n>{ExportUtils._escape_xml(name)}</n>')
            kml_content.append('    <description>Exported from iOS Forensics Tool</description>')
            
            # Add placemarks for each location
            placemark_count = 0
            for item in data:
                lat = item.get('latitude')
                lon = item.get('longitude')
                
                # Skip if no coordinates
                if lat is None or lon is None:
                    continue
                
                placemark_count += 1
                
                # Build description from available fields (excluding latitude, longitude, and name)
                description_parts = []
                for key, value in item.items():
                    if key not in ['latitude', 'longitude', 'name']:
                        if isinstance(value, datetime):
                            description_parts.append(f"{key}: {value.isoformat()}")
                        else:
                            description_parts.append(f"{key}: {value}")
                
                description = '<br/>'.join(description_parts)

                # Adds ExtendedData from available fields (excluding latitude, longitude, and name - to match your description)
                # So description info is shown when imported into Google Earth or other mapping applications to visualize location data
                extended_data_lines = []
                for key, value in item.items():
                    if key not in ['latitude', 'longitude', 'name']:
                        escaped_key = ExportUtils._escape_xml(str(key))
                        escaped_value = ExportUtils._escape_xml(str(value))
                        extended_data_lines.append(
                            f'        <Data name="{escaped_key}"><value>{escaped_value}</value></Data>'
                        )
                
                # Get name for placemark
                placemark_name = item.get('name', item.get('uuid', f'Location {placemark_count}'))
                
                kml_content.append('    <Placemark>')
                kml_content.append(f'      <n>{ExportUtils._escape_xml(str(placemark_name))}</n>')
                kml_content.append(f'      <description>{ExportUtils._escape_xml(description)}</description>')
                kml_content.append('      <ExtendedData>')
                kml_content.extend(extended_data_lines)
                kml_content.append('      </ExtendedData>')
                kml_content.append('      <Point>')
                kml_content.append(f'        <coordinates>{lon},{lat},0</coordinates>')
                kml_content.append('      </Point>')
                kml_content.append('    </Placemark>')
            
            # Close KML document
            kml_content.append('  </Document>')
            kml_content.append('</kml>')
            
            # Write to file
            with open(output_path, 'w', encoding='utf-8') as kml_file:
                kml_file.write('\n'.join(kml_content))
            
            print(f"Successfully exported {placemark_count} locations to KML: {output_path}")
            return True
            
        except Exception as e:
            print(f"Error exporting to KML: {str(e)}")
            return False
    
    @staticmethod
    def _escape_xml(text: str) -> str:
        """
        Escape special XML characters.
        
        Args:
            text: Text to escape
            
        Returns:
            XML-safe text
        """
        if text is None:
            return ''
        
        text = str(text)
        replacements = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&apos;'
        }
        for old, new in replacements.items():
            text = text.replace(old, new)
        return text


class WildModeExporter:
    """Export utilities specifically for WildModeAssociationRecord data."""
    
    @staticmethod
    def to_csv_format(records: List) -> List[Dict[str, Any]]:
        """
        Convert WildModeRecord objects to CSV-friendly dictionaries.
        
        Location data comes first, followed by a summary section at the end
        containing First_Seen, Trigger_DateTime, and Update (if present).
        
        Args:
            records: List of WildModeRecord objects
            
        Returns:
            List of dictionaries ready for CSV export
        """
        csv_data = []
        
        # Define the fieldnames for location rows (without First_Seen and Trigger_DateTime)
        location_fieldnames = ['UUID', 'Manufacturer', 'Model', 'Tracker_UUID', 
                               'MAC_Addresses', 'Location_Count', 'Location_Number',
                               'Latitude', 'Longitude', 'Timestamp', 'Horizontal_Accuracy']
        
        # Track summary values (will be same across all records from same tracker)
        first_seen_value = None
        trigger_datetime_value = None
        observation_states = {}  # Dictionary to collect all observation states
        
        for record in records:
            # Capture summary values from the first record that has them
            if first_seen_value is None and record.first_seen:
                first_seen_value = record.first_seen
            if trigger_datetime_value is None and record.trigger_datetime:
                trigger_datetime_value = record.trigger_datetime
            # Collect observation states from the record
            if hasattr(record, 'observation_states') and record.observation_states:
                for state_name, state_timestamp in record.observation_states.items():
                    # Only add if we haven't seen this state yet
                    if state_name not in observation_states:
                        observation_states[state_name] = state_timestamp
            
            # Create base record info (without First_Seen and Trigger_DateTime)
            base_dict = {
                'UUID': record.uuid,
                'Manufacturer': record.manufacturer or '',
                'Model': record.model or '',
                'Tracker_UUID': record.tracker_uuid or '',
                'MAC_Addresses': ', '.join(record.mac_addresses),
                'Location_Count': len(record.locations)
            }
            
            # If there are locations, create a row for each location
            if record.locations:
                for i, loc in enumerate(record.locations, 1):
                    row = base_dict.copy()
                    row['Location_Number'] = i
                    row['Latitude'] = loc.get('latitude', '')
                    row['Longitude'] = loc.get('longitude', '')
                    row['Timestamp'] = loc.get('timestamp', '')
                    row['Horizontal_Accuracy'] = loc.get('horizontal_accuracy', '')
                    csv_data.append(row)
            else:
                # No locations, add base info only
                base_dict['Location_Number'] = ''
                base_dict['Latitude'] = ''
                base_dict['Longitude'] = ''
                base_dict['Timestamp'] = ''
                base_dict['Horizontal_Accuracy'] = ''
                csv_data.append(base_dict)
        
        # Add summary section at the end
        # Two blank rows for spacing
        blank_row = {field: '' for field in location_fieldnames}
        csv_data.append(blank_row)
        csv_data.append(blank_row)
        
        # First_Seen row
        first_seen_row = {field: '' for field in location_fieldnames}
        first_seen_row['UUID'] = 'First_Seen'
        first_seen_row['Manufacturer'] = first_seen_value if first_seen_value else ''
        csv_data.append(first_seen_row)
        
        # Trigger_DateTime row
        trigger_row = {field: '' for field in location_fieldnames}
        trigger_row['UUID'] = 'Trigger_DateTime'
        trigger_row['Manufacturer'] = trigger_datetime_value if trigger_datetime_value else ''
        csv_data.append(trigger_row)
        
        # Add all observation states (e.g., 'update', 'staged', 'notify')
        for state_name, state_timestamp in observation_states.items():
            state_row = {field: '' for field in location_fieldnames}
            state_row['UUID'] = state_name
            state_row['Manufacturer'] = state_timestamp if state_timestamp else ''
            csv_data.append(state_row)
        
        return csv_data
    
    @staticmethod
    def to_csv_format_single(record) -> List[Dict[str, Any]]:
        """
        Convert a single WildModeRecord object to CSV-friendly dictionaries.
        
        Args:
            record: A single WildModeRecord object
            
        Returns:
            List of dictionaries ready for CSV export (one per location)
        """
        return WildModeExporter.to_csv_format([record])
    
    @staticmethod
    def to_kml_format(records: List) -> List[Dict[str, Any]]:
        """
        Convert WildModeRecord objects to KML-friendly dictionaries.
        
        Args:
            records: List of WildModeRecord objects
            
        Returns:
            List of dictionaries with location data for KML export
        """
        kml_data = []
        
        for record in records:
            for i, loc in enumerate(record.locations, 1):
                # Get timestamp for name (for chronological ordering)
                timestamp = loc.get('timestamp', '')
                timestamp_str = timestamp.isoformat() if hasattr(timestamp, 'isoformat') else str(timestamp)
                
                # Use only timestamp as the name for easy chronological sorting
                name = timestamp_str if timestamp_str else 'Unknown Time'
                
                # Manufacturer and model go in the description
                manufacturer = record.manufacturer or 'Unknown'
                model = record.model or 'Unknown'
                
                kml_item = {
                    'name': name,
                    'uuid': record.uuid,
                    'tracker_uuid': record.tracker_uuid or '',
                    'manufacturer': manufacturer,
                    'model': model,
                    'location_number': i,
                    'latitude': loc.get('latitude'),
                    'longitude': loc.get('longitude'),
                    'timestamp': timestamp_str,
                    'accuracy': f"{loc.get('horizontal_accuracy', 'Unknown')} meters",
                    'mac_addresses': ', '.join(record.mac_addresses),
                    'trigger_datetime': record.trigger_datetime or ''
                }
                kml_data.append(kml_item)
        
        return kml_data


class BeaconNamingExporter:
    """Export utilities specifically for BeaconNamingRecord data."""
    
    @staticmethod
    def to_csv_format(records: List) -> List[Dict[str, Any]]:
        """
        Convert BeaconNamingRecord objects to CSV-friendly dictionaries.
        
        Args:
            records: List of BeaconNamingRecord objects
            
        Returns:
            List of dictionaries ready for CSV export
        """
        csv_data = []
        
        for record in records:
            csv_data.append({
                'Record_UUID': record.uuid,
                'Name': record.name or '',
                'Emoji': record.emoji or '',
                'Associated_Beacon': record.associated_beacon or ''
            })
        
        return csv_data


class OwnedBeaconsExporter:
    """Export utilities specifically for OwnedBeacons data."""
    
    @staticmethod
    def to_csv_format(records: List) -> List[Dict[str, Any]]:
        """
        Convert OwnedBeaconRecord objects to CSV-friendly dictionaries.
        
        Args:
            records: List of OwnedBeaconRecord objects
            
        Returns:
            List of dictionaries ready for CSV export
        """
        csv_data = []
        
        for record in records:
            csv_data.append({
                'Identifier': record.identifier or '',
                'Model': record.model or '',
                'Custom_Name': record.custom_name or '',
                'Emoji': record.emoji or '',
                'Pairing_Date': record.pairing_date,
                'Stable_Identifier': record.stable_identifier or '',
                'Filename': record.filename,
                'Public_Key_Hex': record.public_key_hex or '',
                'Private_Key_Hex': record.private_key_hex or '',
                'Private_Scalar_Hex': record.private_scalar_hex or '',
                'Shared_Secret_Hex': record.shared_secret_hex or '',
                'Secondary_Shared_Secret_Hex': record.secondary_shared_secret_hex or '',
                'Secure_Locations_Shared_Secret_Hex': record.secure_locations_shared_secret_hex or '',
            })
        
        return csv_data


class SafeLocationsExporter:
    """Export utilities specifically for SafeLocations data."""
    
    @staticmethod
    def to_csv_format(records: List) -> List[Dict[str, Any]]:
        """
        Convert SafeLocationRecord objects to CSV-friendly dictionaries.
        
        Args:
            records: List of SafeLocationRecord objects
            
        Returns:
            List of dictionaries ready for CSV export
        """
        csv_data = []
        
        for record in records:
            # Get beacon names/UUIDs as comma-separated list
            beacon_info = []
            for beacon_uuid in record.associated_beacons:
                beacon_name = record.beacon_names.get(beacon_uuid)
                if beacon_name and beacon_name != beacon_uuid:
                    beacon_info.append(f"{beacon_name} ({beacon_uuid})")
                else:
                    beacon_info.append(beacon_uuid)
            
            # Get timestamps
            timestamp1 = record.timestamps[0] if len(record.timestamps) > 0 else None
            timestamp2 = record.timestamps[1] if len(record.timestamps) > 1 else None
            
            csv_data.append({
                'UUID': record.uuid,
                'Name': record.name or '(Unnamed)',
                'Latitude': record.latitude,
                'Longitude': record.longitude,
                'Radius_Meters': record.radius,
                'Timestamp_1': timestamp1,
                'Timestamp_2': timestamp2,
                'Associated_Beacons_Count': len(record.associated_beacons),
                'Associated_Beacons': '; '.join(beacon_info) if beacon_info else ''
            })
        
        return csv_data
    
    @staticmethod
    def to_kml_format(records: List) -> List[Dict[str, Any]]:
        """
        Convert SafeLocationRecord objects to KML-friendly dictionaries.
        
        Args:
            records: List of SafeLocationRecord objects
            
        Returns:
            List of dictionaries with location data for KML export
        """
        kml_data = []
        
        for record in records:
            # Get beacon names/UUIDs for description
            beacon_info = []
            for beacon_uuid in record.associated_beacons:
                beacon_name = record.beacon_names.get(beacon_uuid)
                if beacon_name and beacon_name != beacon_uuid:
                    beacon_info.append(f"{beacon_name} ({beacon_uuid})")
                else:
                    beacon_info.append(beacon_uuid)
            
            # Get timestamps
            timestamp1 = record.timestamps[0] if len(record.timestamps) > 0 else None
            timestamp2 = record.timestamps[1] if len(record.timestamps) > 1 else None
            
            kml_item = {
                'name': record.name or '(Unnamed Safe Location)',
                'uuid': record.uuid,
                'latitude': record.latitude,
                'longitude': record.longitude,
                'radius': f"{record.radius} meters" if record.radius else 'Unknown',
                'timestamp_1': timestamp1 or 'Unknown',
                'timestamp_2': timestamp2 or 'Unknown',
                'associated_beacons': '<br/>'.join(beacon_info) if beacon_info else 'None'
            }
            kml_data.append(kml_item)
        
        return kml_data


class SharedBeaconsExporter:
    """Export utilities specifically for SharedBeacons data."""
    
    @staticmethod
    def to_csv_format(records: List) -> List[Dict[str, Any]]:
        """
        Convert SharedBeaconRecord objects to CSV-friendly dictionaries.
        
        Args:
            records: List of SharedBeaconRecord objects
            
        Returns:
            List of dictionaries ready for CSV export
        """
        csv_data = []
        
        for record in records:
            csv_data.append({
                'Record_UUID': record.uuid,
                'Beacon_Identifier': record.identifier or '',
                'Beacon_Name': record.beacon_name or '(Not assigned)',
                'Shared_By': record.destination or '',
                'Share_Date': record.share_date
            })
        
        return csv_data


class BeaconEstimatedLocationExporter:
    """Export utilities specifically for BeaconEstimatedLocation data."""
    
    @staticmethod
    def to_csv_format(records: List) -> List[Dict[str, Any]]:
        """
        Convert BeaconEstimatedLocationRecord objects to CSV-friendly dictionaries.
        
        Args:
            records: List of BeaconEstimatedLocationRecord objects
            
        Returns:
            List of dictionaries ready for CSV export
        """
        csv_data = []
        
        for record in records:
            csv_data.append({
                'Record_UUID': record.uuid,
                'Beacon_UUID': record.beacon_uuid,
                'Beacon_Name': record.beacon_name or '',
                'Latitude': record.latitude,
                'Longitude': record.longitude,
                'Horizontal_Accuracy': record.horizontal_accuracy,
                'Timestamp': record.timestamp
            })
        
        return csv_data
    
    @staticmethod
    def to_kml_format(records: List) -> List[Dict[str, Any]]:
        """
        Convert BeaconEstimatedLocationRecord objects to KML-friendly dictionaries.
        
        Args:
            records: List of BeaconEstimatedLocationRecord objects
            
        Returns:
            List of dictionaries with location data for KML export
        """
        kml_data = []
        
        for record in records:
            # Get timestamp for name (requirement: timestamp in placemark name)
            timestamp = record.timestamp
            timestamp_str = timestamp.isoformat() if hasattr(timestamp, 'isoformat') else str(timestamp)
            
            # Use timestamp as the name for chronological sorting in mapping software
            name = timestamp_str if timestamp_str else 'Unknown Time'
            
            kml_item = {
                'name': name,
                'record_uuid': record.uuid,
                'beacon_uuid': record.beacon_uuid,
                'beacon_name': record.beacon_name or '(Not set)',
                'latitude': record.latitude,
                'longitude': record.longitude,
                'timestamp': timestamp_str,
                'accuracy': f"{record.horizontal_accuracy} meters" if record.horizontal_accuracy else 'Unknown'
            }
            kml_data.append(kml_item)
        
        return kml_data


class OwnerSharingCircleExporter:
    """Export utilities specifically for OwnerSharingCircle data."""
    
    @staticmethod
    def to_csv_format(records: List) -> List[Dict[str, Any]]:
        """
        Convert OwnerSharingCircleRecord objects to CSV-friendly dictionaries.
        
        Args:
            records: List of OwnerSharingCircleRecord objects
            
        Returns:
            List of dictionaries ready for CSV export
        """
        csv_data = []
        
        for record in records:
            # Extract member UUIDs and acceptance states
            member_uuids = []
            member_acceptance_states = []
            
            for member in record.members:
                if isinstance(member, str):
                    member_uuids.append(member)
                    member_acceptance_states.append('N/A')
                elif isinstance(member, dict):
                    member_uuids.append('N/A')
                    member_acceptance_states.append(str(member.get('acceptanceState', 'Unknown')))
            
            csv_data.append({
                'Record_ID': record.identifier or '',
                'Beacon_ID': record.beacon_identifier or '',
                'Beacon_Name': record.beacon_name or '(Not enriched)',
                'Beacon_Emoji': record.beacon_emoji or '',
                'Acceptance_State': record.acceptance_state,
                'Sharing_Circle_Type': record.sharing_circle_type,
                'Member_Count': len(record.members),
                'Member_UUIDs': '; '.join(member_uuids),
                'Member_Acceptance_States': '; '.join(member_acceptance_states)
            })
        
        return csv_data


class OwnerPeerTrustExporter:
    """Export utilities specifically for OwnerPeerTrust data."""
    
    @staticmethod
    def to_csv_format(records: List) -> List[Dict[str, Any]]:
        """
        Convert OwnerPeerTrustRecord objects to CSV-friendly dictionaries.
        
        Args:
            records: List of OwnerPeerTrustRecord objects
            
        Returns:
            List of dictionaries ready for CSV export
        """
        csv_data = []
        
        for record in records:
            # Format beacon names if available
            beacon_names_str = ''
            if record.beacon_names:
                beacon_parts = []
                for name, emoji in record.beacon_names:
                    emoji_str = f" {emoji}" if emoji else ""
                    beacon_parts.append(f"{name}{emoji_str}")
                beacon_names_str = '; '.join(beacon_parts)
            
            csv_data.append({
                'Record_ID': record.identifier or '',
                'Display_Identifier': record.display_identifier or '',
                'Destination': record.destination or '',
                'Sharing_Timestamp': record.sharing_timestamp,
                'State': record.state,
                'Type': record.peer_trust_type,
                'Shared_Beacons': beacon_names_str
            })
        
        return csv_data


class KeysFileExporter:
    """
    Export utilities for advertisement key cache data parsed by
    KeysDirectoryParser (or a flat list of KeyEntry objects).

    CSV columns
    -----------
    Beacon_UUID      : folder UUID (links to OwnedBeacons / BeaconNamingRecord)
    Key_Type         : "primary", "secondary", or "primary_advertisements"
    Beacon_Name      : friendly name from BeaconNamingRecord (blank if not enriched)
    Beacon_Emoji     : emoji from BeaconNamingRecord          (blank if not enriched)
    Key_ID           : integer key ID (e.g. 41848)
    Symmetric_Key_Hex : 32-byte AES-256 symmetric rolling key as hex
    Private_Key_Hex   : 28-byte P-224 private key as hex (SENSITIVE — decrypts reports)
    Public_Key_Hex    : 28-byte P-224 public key as hex
    Report_ID_base64 : base64(SHA-256(p_i)) — Apple acsnservice/fetch lookup ID
    """

    CSV_COLUMNS = [
        "Beacon_Name",
        "Beacon_UUID",
        "Key_Type",
        "Beacon_Emoji",
        "Key_ID",
        "Symmetric_Key_Hex",
        "Private_Key_Hex",
        "Public_Key_Hex",
        "Report_ID_base64",
    ]

    @staticmethod
    def to_csv_format(entries: list) -> List[Dict[str, Any]]:
        """
        Convert a list of KeyEntry objects to a list of CSV-ready dicts.

        Args:
            entries: list of KeyEntry (from KeysFileParser or KeysDirectoryParser)

        Returns:
            List of dicts with string values, one per key entry.
        """
        rows = []
        for e in entries:
            rows.append({
                "Beacon_Name":      getattr(e, "beacon_name",  "") or "",
                "Beacon_UUID":      getattr(e, "beacon_uuid",  "") or "",
                "Key_Type":         getattr(e, "key_type",     "primary"),
                "Beacon_Emoji":     getattr(e, "beacon_emoji", "") or "",
                "Key_ID":           getattr(e, "key_id",       ""),
                "Symmetric_Key_Hex": getattr(e, "sk_i_hex",  ""),
                "Private_Key_Hex":   getattr(e, "d_i_hex",   ""),
                "Public_Key_Hex":    getattr(e, "p_i_hex",   ""),
                "Report_ID_base64":  getattr(e, "report_id", ""),
            })
        return rows

    @staticmethod
    def write_csv(entries: list, output_path: str) -> int:
        """
        Write all key entries to a CSV file.

        Args:
            entries:     list of KeyEntry objects
            output_path: destination file path (will be created / overwritten)

        Returns:
            Number of rows written.
        """
        rows = KeysFileExporter.to_csv_format(entries)
        if not rows:
            return 0

        with open(output_path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=KeysFileExporter.CSV_COLUMNS)
            writer.writeheader()
            writer.writerows(rows)

        return len(rows)

    @staticmethod
    def to_csv_string(entries: list) -> str:
        """
        Return the CSV as a string (useful for preview dialogs or clipboard copy).

        Args:
            entries: list of KeyEntry objects

        Returns:
            UTF-8 CSV string including header row.
        """
        rows = KeysFileExporter.to_csv_format(entries)
        if not rows:
            return ""

        buf = io.StringIO()
        writer = csv.DictWriter(
            buf,
            fieldnames=KeysFileExporter.CSV_COLUMNS,
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(rows)
        return buf.getvalue()

    @staticmethod
    def summary_by_beacon(entries: list) -> List[Dict[str, Any]]:
        """
        Produce a one-row-per-beacon summary (for a quick overview table in the GUI).

        Columns: Beacon_UUID, Beacon_Name, Beacon_Emoji,
                 Primary_Keys, Primary_Hours,
                 Secondary_Keys, Secondary_Hours,
                 Primary_Advertisements_Keys, Primary_Advertisements_Hours,
                 Total_Keys
        """
        agg: Dict[str, Dict] = {}
        for e in entries:
            uuid = getattr(e, "beacon_uuid", "") or "unknown"
            if uuid not in agg:
                agg[uuid] = {
                    "Beacon_UUID":                 uuid,
                    "Beacon_Name":                 getattr(e, "beacon_name",  "") or "",
                    "Beacon_Emoji":                getattr(e, "beacon_emoji", "") or "",
                    "Primary_Keys":                0,
                    "Secondary_Keys":              0,
                    "Primary_Advertisements_Keys": 0,
                }
            kt = getattr(e, "key_type", "primary")
            if kt == "primary":
                agg[uuid]["Primary_Keys"] += 1
            elif kt == "secondary":
                agg[uuid]["Secondary_Keys"] += 1
            else:  # primary_advertisements (or any future type)
                agg[uuid]["Primary_Advertisements_Keys"] += 1
            # Update name/emoji in case early entries were not yet enriched
            if not agg[uuid]["Beacon_Name"] and getattr(e, "beacon_name", ""):
                agg[uuid]["Beacon_Name"]  = e.beacon_name
                agg[uuid]["Beacon_Emoji"] = e.beacon_emoji or ""

        result = []
        for row in agg.values():
            p  = row["Primary_Keys"]
            s  = row["Secondary_Keys"]
            pa = row["Primary_Advertisements_Keys"]
            row["Primary_Hours"]                = round(p  * 15 / 60, 1)
            row["Secondary_Hours"]              = round(s  * 15 / 60, 1)
            row["Primary_Advertisements_Hours"] = round(pa * 15 / 60, 1)
            row["Total_Keys"]                   = p + s + pa
            result.append(row)

        return sorted(result, key=lambda r: r["Beacon_UUID"])


class WildModeUnifiedExporter:
    """
    Produces a single-row-per-beacon summary CSV for Wild Mode records.

    Each row represents one WildModeAssociationRecord file and contains:
      - The beacon UUID
      - The advertisement bytes (hex) and derived MAC address
      - The first and last observed location with timestamps and coordinates

    This output is intended as a comparison target analogous to the
    Observations.db CSV export — one row per tracker, not one row per
    location point.

    Columns
    -------
    UUID                  : WildModeAssociationRecord file UUID
    Advertisement_Hex     : Full advertisement bytes as uppercase hex.
                            iOS 17: raw 28-byte advertisement payload.
                            iOS 18: 28-byte advertisement key when present in
                              the plist (preferred); falls back to the 6-byte
                              address bytes when no advertisement key exists.
    Advertisement_MAC     : Derived MAC address (XX:XX:XX:XX:XX:XX), with the
                            BLE static-random address correction (| 0xC0)
                            applied to byte 0.
    First_Seen_Timestamp  : Timestamp of the earliest location entry (ISO 8601)
    First_Seen_Latitude   : Latitude at first seen time
    First_Seen_Longitude  : Longitude at first seen time
    Last_Seen_Timestamp   : Timestamp of the most recent location entry (ISO 8601)
    Last_Seen_Latitude    : Latitude at last seen time
    Last_Seen_Longitude   : Longitude at last seen time
    """

    CSV_COLUMNS = [
        'UUID',
        'Advertisement_Hex',
        'Advertisement_MAC',
        'First_Seen_Timestamp',
        'First_Seen_Latitude',
        'First_Seen_Longitude',
        'Last_Seen_Timestamp',
        'Last_Seen_Latitude',
        'Last_Seen_Longitude',
    ]

    @staticmethod
    def _sort_locations(locations: list) -> list:
        """
        Return the location list sorted ascending by timestamp.
        Entries that have no timestamp are placed at the end so they
        never accidentally become the apparent first or last sighting.
        """
        def _sort_key(loc):
            ts = loc.get('timestamp')
            if isinstance(ts, datetime):
                return (0, ts)
            # No usable timestamp — sort to the end
            return (1, datetime.min)

        return sorted(locations, key=_sort_key)

    @staticmethod
    def _advertisement_hex(record) -> str:
        """
        Return the raw advertisement / address bytes as an uppercase hex string.

        Priority order:
          1. raw_advertisement (28 bytes) — present on iOS 17 records and on
             iOS 18 records whose plist includes the 'advertisement' key.
          2. raw_address (6 bytes) — fallback for iOS 18 records that have
             no 'advertisement' key in the plist.
          3. Empty string if neither is available.
        """
        raw = getattr(record, 'raw_advertisement', None) or getattr(record, 'raw_address', None)
        if isinstance(raw, (bytes, bytearray)):
            return raw.hex().upper()
        return ''

    @staticmethod
    def _format_timestamp(loc) -> str:
        """Return the location timestamp as an ISO 8601 string, or empty string."""
        if loc is None:
            return ''
        ts = loc.get('timestamp', '')
        if isinstance(ts, datetime):
            return ts.isoformat()
        return str(ts) if ts else ''

    @staticmethod
    def to_csv_format(records: list) -> List[Dict[str, Any]]:
        """
        Convert a list of WildModeRecord objects into CSV-ready dicts.

        One row is produced per record (i.e. per beacon UUID).  Locations
        are sorted by timestamp before the first and last are selected.

        Args:
            records: List of WildModeRecord objects

        Returns:
            List of dicts keyed by CSV_COLUMNS, ready for ExportUtils.export_to_csv()
        """
        rows = []
        for record in records:
            adv_hex = WildModeUnifiedExporter._advertisement_hex(record)
            adv_mac = record.mac_addresses[0] if record.mac_addresses else ''

            sorted_locs = WildModeUnifiedExporter._sort_locations(record.locations)
            first_loc = sorted_locs[0]  if sorted_locs else None
            last_loc  = sorted_locs[-1] if sorted_locs else None

            rows.append({
                'UUID':                 record.uuid,
                'Advertisement_Hex':   adv_hex,
                'Advertisement_MAC':   adv_mac,
                'First_Seen_Timestamp': WildModeUnifiedExporter._format_timestamp(first_loc),
                'First_Seen_Latitude':  first_loc.get('latitude',  '') if first_loc else '',
                'First_Seen_Longitude': first_loc.get('longitude', '') if first_loc else '',
                'Last_Seen_Timestamp':  WildModeUnifiedExporter._format_timestamp(last_loc),
                'Last_Seen_Latitude':   last_loc.get('latitude',  '') if last_loc else '',
                'Last_Seen_Longitude':  last_loc.get('longitude', '') if last_loc else '',
            })
        return rows

    @staticmethod
    def write_csv(records: list, output_path: str) -> int:
        """
        Export unified Wild Mode records directly to a CSV file.

        Args:
            records:     List of WildModeRecord objects
            output_path: Destination file path (created / overwritten)

        Returns:
            Number of rows written.
        """
        rows = WildModeUnifiedExporter.to_csv_format(records)
        if not rows:
            return 0

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, 'w', newline='', encoding='utf-8') as fh:
            writer = csv.DictWriter(fh, fieldnames=WildModeUnifiedExporter.CSV_COLUMNS)
            writer.writeheader()
            writer.writerows(rows)

        return len(rows)


# Example usage
if __name__ == "__main__":
    print("Export utilities module - import this in your parsers")
    print("\nExample usage:")
    print("  from export_utils import ExportUtils, WildModeExporter")
    print("  ")
    print("  # For WildMode records:")
    print("  csv_data = WildModeExporter.to_csv_format(records)")
    print("  ExportUtils.export_to_csv(csv_data, 'output.csv')")
    print("  ")
    print("  kml_data = WildModeExporter.to_kml_format(records)")
    print("  ExportUtils.export_to_kml(kml_data, 'output.kml', 'Tracker Locations')")
