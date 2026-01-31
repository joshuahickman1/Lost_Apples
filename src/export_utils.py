"""
Export Utilities
This module provides CSV and KML export functionality for parsed iOS forensic data.
"""

import csv
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
            kml_content.append(f'    <name>{ExportUtils._escape_xml(name)}</name>')
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
                kml_content.append(f'      <name>{ExportUtils._escape_xml(str(placemark_name))}</name>')
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
                'Filename': record.filename
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
