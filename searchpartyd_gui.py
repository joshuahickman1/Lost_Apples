"""
Lost Apples
A graphical interface for parsing iOS Find My network and AirTag tracking data.

This GUI provides an interface to:
1. Extract BeaconStore encryption key from iOS keychain files
2. Parse WildModeAssociationRecord (unwanted tracker alerts)
3. Parse BeaconNamingRecord (custom tracker names/emojis)
4. Parse OwnedBeacons (device pairing information)
5. Parse SafeLocations (safe locations)
6. Parse BeaconEstimatedLocation (beacon location history)
7. Parse SharedBeacons (beacons shared with user)
8. Parse OwnerSharingCircle (beacons shared BY user)
9. Parse OwnerPeerTrust (people with whom beacons are shared)
10. Export results to CSV and KML formats
11. Decrypt Observations.db database (device observations with locations)
12. Process full iOS extraction zip files directly

All individual parsers can still be run independently from the command line.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from pathlib import Path
import sys
import threading
from datetime import datetime
from typing import Optional

# Import PIL for image handling (logo display)
try:
    from PIL import Image, ImageTk
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False


class ToolTip:
    """
    Create a tooltip for a given widget.
    
    Usage:
        button = ttk.Button(root, text="My Button")
        ToolTip(button, "This is a helpful tooltip!")
    """
    
    def __init__(self, widget, text: str, delay: int = 500):
        """
        Initialize the tooltip.
        
        Args:
            widget: The tkinter widget to attach the tooltip to
            text: The tooltip text to display
            delay: Delay in milliseconds before showing the tooltip (default 500ms)
        """
        self.widget = widget
        self.text = text
        self.delay = delay
        self.tooltip_window = None
        self.scheduled_id = None
        
        # Bind mouse events
        widget.bind("<Enter>", self._on_enter)
        widget.bind("<Leave>", self._on_leave)
        widget.bind("<ButtonPress>", self._on_leave)  # Hide on click
    
    def _on_enter(self, event=None):
        """Schedule tooltip to appear after delay."""
        self._cancel_scheduled()
        self.scheduled_id = self.widget.after(self.delay, self._show_tooltip)
    
    def _on_leave(self, event=None):
        """Hide tooltip and cancel any scheduled show."""
        self._cancel_scheduled()
        self._hide_tooltip()
    
    def _cancel_scheduled(self):
        """Cancel any scheduled tooltip show."""
        if self.scheduled_id:
            self.widget.after_cancel(self.scheduled_id)
            self.scheduled_id = None
    
    def _show_tooltip(self):
        """Display the tooltip."""
        if self.tooltip_window:
            return  # Already showing
        
        # Get widget position
        x = self.widget.winfo_rootx()
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 5
        
        # Create tooltip window
        self.tooltip_window = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)  # Remove window decorations
        tw.wm_geometry(f"+{x}+{y}")
        
        # Create tooltip label with styling
        label = tk.Label(
            tw,
            text=self.text,
            justify=tk.LEFT,
            background="#ffffe0",  # Light yellow background
            foreground="#000000",  # Black text
            relief=tk.SOLID,
            borderwidth=1,
            font=("TkDefaultFont", 9),
            padx=6,
            pady=4,
            wraplength=350  # Wrap long text
        )
        label.pack()
    
    def _hide_tooltip(self):
        """Hide the tooltip."""
        if self.tooltip_window:
            self.tooltip_window.destroy()
            self.tooltip_window = None

# Import the parsers
from src.keychain_parser import KeychainParser
from src.ios_keychain_extractor import iOSKeychainExtractor
from src.wild_mode_parser import WildModeParser
from src.beacon_naming_parser import BeaconNamingParser
from src.owned_beacons_parser import OwnedBeaconsParser
from src.safe_locations_parser import SafeLocationsParser
from src.beacon_estimated_location_parser import BeaconEstimatedLocationParser
from src.shared_beacons_parser import SharedBeaconsParser
from src.owner_sharing_circle_parser import OwnerSharingCircleParser
from src.owner_peer_trust_parser import OwnerPeerTrustParser
from src.unified_zip_handler import UnifiedZipHandler, is_zip_file
from src.observations_decryptor import ObservationsDecryptor
from src.observations_query_handler import ObservationsQueryHandler
from src.plist_exporter import PlistExporter


class SearchpartydGUI:
    """Main GUI application for Lost Apples."""
    
    def __init__(self, root):
        """
        Initialize the GUI application.
        
        Args:
            root: The tkinter root window
        """
        self.root = root
        self.root.title("Lost Apples 1.0")
        self.root.geometry("900x700")
        self.root.resizable(True, True)
        
        # Variables for file paths
        self.searchpartyd_path = tk.StringVar()
        self.keychain_path = tk.StringVar()
        
        # Zip file handling
        self.zip_handler: Optional[UnifiedZipHandler] = None
        self.using_zip = False
        
        # Variables for extracted data
        self.beacon_store_key: Optional[bytes] = None
        self.observations_key: Optional[bytes] = None
        self.keychain_extractor: Optional[iOSKeychainExtractor] = None
        self.observations_db_decrypted: Optional[str] = None  # Path to decrypted Observations.db
        self.observations_wal_decrypted: Optional[str] = None  # Path to decrypted WAL file
        self.log_entries = []
        
        # Store parsed records for export
        self.wild_mode_records = []
        self.beacon_naming_records = []
        self.owned_beacon_records = []
        self.safe_location_records = []
        self.beacon_location_records = []
        self.shared_beacon_records = []
        self.owner_sharing_circle_records = []
        self.owner_peer_trust_records = []
        
        # Processing flag
        self.is_processing = False
        
        # Option to export decrypted plists
        self.export_plists_var = tk.BooleanVar(value=False)
        
        # Setup the GUI
        self._setup_ui()
        
    def _setup_ui(self):
        """Create all UI elements."""
        # Main container with padding
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights for resizing
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(3, weight=1)  # Status window gets extra space
        
        # Title section
        self._create_title_section(main_frame)
        
        # Input section
        self._create_input_section(main_frame)
        
        # Control buttons
        self._create_control_section(main_frame)
        
        # Status window
        self._create_status_section(main_frame)
        
        # Action buttons
        self._create_action_buttons(main_frame)
        
    def _create_title_section(self, parent):
        """Create the title section with logo."""
        title_frame = ttk.Frame(parent)
        title_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 15))
        title_frame.columnconfigure(1, weight=1)  # Allow middle column to expand
        
        # Left side: Title and subtitle
        text_frame = ttk.Frame(title_frame)
        text_frame.grid(row=0, column=0, sticky=tk.W)
        
        title_label = ttk.Label(
            text_frame,
            text="Lost Apples 1.0",
            font=("TkDefaultFont", 16, "bold")
        )
        title_label.grid(row=0, column=0, sticky=tk.W)
        
        subtitle_label = ttk.Label(
            text_frame,
            text="iOS FindMy Network & Bluetooth Tracker Data Parser",
            font=("TkDefaultFont", 12)
        )
        subtitle_label.grid(row=1, column=0, sticky=tk.W)
        
        author_label = ttk.Label(
            text_frame,
            text="The Binary Hick (https://thebinaryhick.blog)",
            font=("TkDefaultFont", 11)
        )
        author_label.grid(row=2, column=0, sticky=tk.W)
        
        # Right side: Logo
        self._load_logo(title_frame)
    
    def _load_logo(self, parent_frame):
        """
        Load and display the application logo.
        
        The logo is resized to fit nicely in the title area (80px height)
        while maintaining aspect ratio.
        
        Args:
            parent_frame: The frame to place the logo in
        """
        if not PIL_AVAILABLE:
            # PIL not installed, skip logo
            return
        
        # Path to the logo file
        logo_path = Path(__file__).parent / "lost_apple_graphic.png"
        
        if not logo_path.exists():
            # Try alternate location (same directory as script)
            logo_path = Path("lost_apple_graphic.png")
            if not logo_path.exists():
                # Logo not found, skip silently
                return
        
        try:
            # Open and resize the image
            original_image = Image.open(logo_path)
            
            # Calculate new size maintaining aspect ratio
            # Target height of 80 pixels for a nice fit in the header
            target_height = 80
            aspect_ratio = original_image.width / original_image.height
            target_width = int(target_height * aspect_ratio)
            
            # Resize using high-quality resampling
            resized_image = original_image.resize(
                (target_width, target_height),
                Image.Resampling.LANCZOS
            )
            
            # Convert to PhotoImage for tkinter
            # Store as instance variable to prevent garbage collection
            self.logo_image = ImageTk.PhotoImage(resized_image)
            
            # Create label to display the logo
            logo_label = ttk.Label(parent_frame, image=self.logo_image)
            logo_label.grid(row=0, column=2, sticky=tk.E, padx=(20, 0))
            
        except Exception as e:
            # If anything goes wrong loading the logo, just skip it
            # Don't disrupt the user experience
            print(f"Note: Could not load logo: {e}")
        
    def _create_input_section(self, parent):
        """Create the file input section."""
        input_frame = ttk.LabelFrame(parent, text="Input Files", padding="10")
        input_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        input_frame.columnconfigure(1, weight=1)
        
        # searchpartyd folder/zip input
        ttk.Label(input_frame, text="searchpartyd Folder/Zip:").grid(
            row=0, column=0, sticky=tk.W, pady=5
        )
        
        searchpartyd_entry = ttk.Entry(
            input_frame,
            textvariable=self.searchpartyd_path,
            width=50
        )
        searchpartyd_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=5, pady=5)
        
        # Create a frame for the two browse buttons
        browse_frame = ttk.Frame(input_frame)
        browse_frame.grid(row=0, column=2, padx=5, pady=5)
        
        browse_folder_btn = ttk.Button(
            browse_frame,
            text="Folder...",
            command=self._browse_searchpartyd_folder,
            width=10
        )
        browse_folder_btn.grid(row=0, column=0, padx=2)
        
        browse_zip_btn = ttk.Button(
            browse_frame,
            text="Zip...",
            command=self._browse_searchpartyd_zip,
            width=10
        )
        browse_zip_btn.grid(row=0, column=1, padx=2)
        
        # Add tooltip for Zip button
        ToolTip(browse_zip_btn, "Use this button for Premium/Inseyets UFED or Graykey extractions. No need to unzip.")
        
        # Keychain file input
        ttk.Label(input_frame, text="Keychain File:").grid(
            row=1, column=0, sticky=tk.W, pady=5
        )
        
        keychain_entry = ttk.Entry(
            input_frame,
            textvariable=self.keychain_path,
            width=50
        )
        keychain_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=5, pady=5)
        
        browse_keychain_btn = ttk.Button(
            input_frame,
            text="Browse...",
            command=self._browse_keychain_file
        )
        browse_keychain_btn.grid(row=1, column=2, padx=5, pady=5)
        
        # Add tooltips for keychain field and browse button
        keychain_tooltip_text = (
            "It is not necessary to provide the keychain from "
            "Premium/Inseyets UFED zip extractions. They are automatically detected."
        )
        ToolTip(keychain_entry, keychain_tooltip_text)
        ToolTip(browse_keychain_btn, keychain_tooltip_text)
        
        # Export decrypted plists checkbox
        export_plists_check = ttk.Checkbutton(
            input_frame,
            text="Export decrypted bplist files",
            variable=self.export_plists_var
        )
        export_plists_check.grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Add tooltip for export plists checkbox
        ToolTip(
            export_plists_check,
            "When enabled, decrypted binary plist files from .record files will be exported\n"
            "to a 'decrypted_plists' folder in the current directory during analysis.\n"
            "Useful for manual examination of the raw decrypted data."
        )
        
    def _create_control_section(self, parent):
        """Create the control buttons section."""
        control_frame = ttk.Frame(parent)
        control_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        control_frame.columnconfigure(0, weight=1)  # Allow frame to expand
        
        # Inner frame to hold buttons (will be centered)
        buttons_frame = ttk.Frame(control_frame)
        buttons_frame.grid(row=0, column=0)
        
        # Start Analysis button
        self.start_btn = ttk.Button(
            buttons_frame,
            text="Start Analysis",
            command=self._start_analysis,
            width=20
        )
        self.start_btn.grid(row=0, column=0, padx=5)
        
        # Stop button (initially disabled)
        self.stop_btn = ttk.Button(
            buttons_frame,
            text="Stop",
            command=self._stop_analysis,
            width=15,
            state=tk.DISABLED
        )
        self.stop_btn.grid(row=0, column=1, padx=5)
        
        # Progress indicator
        self.progress_var = tk.StringVar(value="Ready")
        progress_label = ttk.Label(
            buttons_frame,
            textvariable=self.progress_var,
            font=("TkDefaultFont", 9, "italic")
        )
        progress_label.grid(row=0, column=2, padx=15, sticky=tk.W)
        
    def _create_status_section(self, parent):
        """Create the status/log window section."""
        status_frame = ttk.LabelFrame(parent, text="Analysis Log", padding="5")
        status_frame.grid(row=3, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        status_frame.columnconfigure(0, weight=1)
        status_frame.rowconfigure(0, weight=1)
        
        # Create scrolled text widget
        self.status_text = scrolledtext.ScrolledText(
            status_frame,
            wrap=tk.WORD,
            width=80,
            height=20,
            font=("Courier", 12)
        )
        self.status_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Configure text tags with colors based on background brightness
        self._configure_log_colors()

    def _is_dark_background(self) -> bool:
        """Detect if the text widget has a dark background."""
        try:
            # Get the background color of the text widget
            bg_color = self.status_text.cget("background")
            # Convert color name to RGB values
            rgb = self.status_text.winfo_rgb(bg_color)
            # RGB values are 16-bit (0-65535), normalize to 0-255
            r, g, b = rgb[0] // 256, rgb[1] // 256, rgb[2] // 256
            # Calculate perceived brightness using luminance formula
            brightness = (0.299 * r + 0.587 * g + 0.114 * b)
            return brightness < 128
        except Exception:
            # Default to light background if detection fails
            return False

    def _configure_log_colors(self):
        """Configure text tag colors based on background brightness."""
        if self._is_dark_background():
            # Bright colors for dark backgrounds
            header_color = "#5DADE2"   # Light sky blue
            success_color = "#58D68D"  # Light green
            error_color = "#F1948A"    # Light coral/salmon
            warning_color = "#F7DC6F"  # Light yellow/gold
        else:
            # Darker colors for light backgrounds
            header_color = "#1A5276"   # Dark blue
            success_color = "#1E8449"  # Dark green
            error_color = "#C0392B"    # Dark red
            warning_color = "#B7950B"  # Dark gold/olive

        self.status_text.tag_config("header", foreground=header_color, font=("Courier", 12, "bold"))
        self.status_text.tag_config("success", foreground=success_color)
        self.status_text.tag_config("error", foreground=error_color)
        self.status_text.tag_config("warning", foreground=warning_color)

    def _create_action_buttons(self, parent):
        """Create the action buttons section."""
        action_frame = ttk.Frame(parent)
        action_frame.grid(row=4, column=0, sticky=(tk.W, tk.E))
        action_frame.columnconfigure(0, weight=1)  # Allow frame to expand
        
        # Row 1: Results buttons (centered) - Export Results and Query Observations on top
        row1_frame = ttk.Frame(action_frame)
        row1_frame.grid(row=0, column=0, pady=(0, 5))
        
        # Export Results button
        self.export_results_btn = ttk.Button(
            row1_frame,
            text="Export Results...",
            command=self._show_export_dialog,
            width=16,
            state=tk.DISABLED
        )
        self.export_results_btn.grid(row=0, column=0, padx=5)
        
        # Query Observations button (initially disabled)
        self.query_obs_btn = ttk.Button(
            row1_frame,
            text="Query Observations...",
            command=self._show_observations_query_dialog,
            width=20,
            state=tk.DISABLED
        )
        self.query_obs_btn.grid(row=0, column=1, padx=5)
        
        # Row 2: Secondary action buttons (centered) - Clear Log, Export Log, Export Keys, About
        row2_frame = ttk.Frame(action_frame)
        row2_frame.grid(row=1, column=0)
        
        # Clear Log button
        clear_btn = ttk.Button(
            row2_frame,
            text="Clear Log",
            command=self._clear_log,
            width=12
        )
        clear_btn.grid(row=0, column=0, padx=5)
        
        # Export Log button
        export_btn = ttk.Button(
            row2_frame,
            text="Export Log",
            command=self._export_log,
            width=12
        )
        export_btn.grid(row=0, column=1, padx=5)
        
        # Export Keys button (initially disabled, enabled after key extraction)
        self.export_keys_btn = ttk.Button(
            row2_frame,
            text="Export Keys",
            command=self._export_keys,
            width=12,
            state=tk.DISABLED
        )
        self.export_keys_btn.grid(row=0, column=2, padx=5)
        
        # Add tooltip for Export Keys button
        ToolTip(
            self.export_keys_btn,
            "Export the extracted encryption keys (BeaconStore and Observations)\n"
            "to a text file in the working directory."
        )
        
        # About button
        about_btn = ttk.Button(
            row2_frame,
            text="About",
            command=self._show_about,
            width=10
        )
        about_btn.grid(row=0, column=3, padx=5)
        
    def _browse_searchpartyd_folder(self):
        """Open dialog to select searchpartyd folder."""
        folder = filedialog.askdirectory(
            title="Select com.apple.icloud.searchpartyd Folder",
            initialdir=Path.home()
        )
        if folder:
            # Clean up any existing zip extraction
            self._cleanup_zip()
            
            self.searchpartyd_path.set(folder)
            self.using_zip = False
            self._log(f"Selected searchpartyd folder: {folder}")
    
    def _browse_searchpartyd_zip(self):
        """Open dialog to select iOS extraction zip file."""
        file = filedialog.askopenfilename(
            title="Select iOS Extraction Zip File",
            initialdir=Path.home(),
            filetypes=[
                ("Zip files", "*.zip"),
                ("All files", "*.*")
            ]
        )
        if file:
            # Validate it's a zip file
            if not is_zip_file(file):
                messagebox.showerror("Invalid File", "Selected file is not a valid zip file.")
                return
            
            # Clean up any existing zip extraction
            self._cleanup_zip()
            
            # Detect zip type using unified handler
            try:
                temp_handler = UnifiedZipHandler(file)
                zip_type = temp_handler.detect_zip_type()
                
                self.searchpartyd_path.set(file)
                self.using_zip = True
                
                if zip_type == 'UFED':
                    self._log(f"Selected UFED extraction zip: {file}")
                    self._log("  Will search for keychain and searchpartyd folder...")
                    
                    # Check if keychain is present
                    info = temp_handler.get_info()
                    if info['has_keychain']:
                        self._log("  ✓ Keychain file detected in zip")
                        # Auto-set keychain path to indicate it will come from zip
                        self.keychain_path.set("[Included in UFED zip]")
                    else:
                        self._log("  ⚠ No keychain found in zip - you'll need to select it separately")
                else:  # Graykey
                    self._log(f"Selected Graykey extraction zip: {file}")
                    self._log("  Will search for Library/com.apple.icloud.searchpartyd/...")
                    
            except Exception as e:
                messagebox.showerror("Zip Analysis Error", f"Error analyzing zip file:\n{str(e)}")
                return
            
    def _browse_keychain_file(self):
        """Open dialog to select keychain plist file."""
        file = filedialog.askopenfilename(
            title="Select Keychain Plist File",
            initialdir=Path.home(),
            filetypes=[
                ("Plist files", "*.plist"),
                ("All files", "*.*")
            ]
        )
        if file:
            self.keychain_path.set(file)
            self._log(f"Selected keychain file: {file}")
    
    def _cleanup_zip(self):
        """Clean up any extracted zip files."""
        if self.zip_handler:
            try:
                self.zip_handler.cleanup()
                self._log("Cleaned up temporary extracted files")
            except:
                pass
            finally:
                self.zip_handler = None
            
    def _log(self, message: str, tag: str = None):
        """
        Add a message to the status log.
        
        Args:
            message: The message to log
            tag: Optional tag for text styling (header, success, error, warning)
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_line = f"[{timestamp}] {message}\n"
        
        # Store in log entries for export
        self.log_entries.append(log_line)
        
        # Display in text widget
        self.status_text.insert(tk.END, log_line, tag)
        self.status_text.see(tk.END)
        self.root.update_idletasks()
        
    def _clear_log(self):
        """Clear the status log."""
        if messagebox.askyesno("Clear Log", "Are you sure you want to clear the log?"):
            self.status_text.delete(1.0, tk.END)
            self.log_entries.clear()
            self._log("Log cleared")
            
    def _export_log(self):
        """Export the log to a text file."""
        if not self.log_entries:
            messagebox.showinfo("Export Log", "Log is empty. Nothing to export.")
            return
            
        file = filedialog.asksaveasfilename(
            title="Export Log",
            defaultextension=".txt",
            filetypes=[
                ("Text files", "*.txt"),
                ("All files", "*.*")
            ],
            initialfile=f"lost_apples_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )
        
        if file:
            try:
                # Use UTF-8 encoding to support Unicode characters (✓, emojis, etc.)
                with open(file, 'w', encoding='utf-8') as f:
                    f.write("="*80 + "\n")
                    f.write("Lost Apples - Analysis Log\n")
                    f.write(f"Exported: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("="*80 + "\n\n")
                    f.writelines(self.log_entries)
                
                messagebox.showinfo("Export Log", f"Log exported successfully to:\n{file}")
                self._log(f"Log exported to: {file}", "success")
                
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export log:\n{str(e)}")
                self._log(f"Export failed: {str(e)}", "error")
    
    def _export_keys(self):
        """
        Export the extracted encryption keys to a text file.
        
        Creates a file named 'extracted_keys_YYYYMMDD_HHMMSS.txt' in the
        current working directory containing the BeaconStore and Observations
        keys in hexadecimal format.
        """
        if not self.beacon_store_key:
            messagebox.showinfo("No Keys", "No keys have been extracted yet.\nRun analysis first.")
            return
        
        # Generate default filename with timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        default_filename = f"extracted_keys_{timestamp}.txt"
        
        # Use the current working directory as default location
        output_path = Path.cwd() / default_filename
        
        try:
            # Use UTF-8 encoding to support Unicode characters (✓, emojis, etc.)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write("="*80 + "\n")
                f.write("Lost Apples - Extracted Encryption Keys\n")
                f.write(f"Exported: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("="*80 + "\n\n")
                
                # BeaconStore Key
                f.write("BeaconStore Key\n")
                f.write("-"*40 + "\n")
                f.write(f"Key (hex): {self.beacon_store_key.hex()}\n")
                f.write(f"Key length: {len(self.beacon_store_key)} bytes\n")
                f.write("\n")
                
                # Observations Key
                f.write("Observations Key\n")
                f.write("-"*40 + "\n")
                if self.observations_key:
                    f.write(f"Key (hex): {self.observations_key.hex()}\n")
                    f.write(f"Key length: {len(self.observations_key)} bytes\n")
                else:
                    f.write("Key: Not found in keychain\n")
                f.write("\n")
                
                f.write("="*80 + "\n")
                f.write("Note: These keys are required to decrypt searchpartyd records\n")
                f.write("and the Observations.db database from this iOS extraction.\n")
            
            messagebox.showinfo(
                "Export Keys", 
                f"Keys exported successfully to:\n{output_path}"
            )
            self._log(f"✓ Keys exported to: {output_path}", "success")
            
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export keys:\n{str(e)}")
            self._log(f"✗ Key export failed: {str(e)}", "error")
                
    def _show_about(self):
        """Show the About dialog."""
        about_text = """Lost Apples - A iOS FindMy & Bluetooth Tracker Data Parser
Version 1.0

A tool for parsing 
FindMy and Bluetooth tracker records from iOS device extractions.

Features:
• Extract searchpartyd keys from iOS keychain
• Parse unwanted tracker alerts (WildModeAssociationRecord)
• Parse custom tracker names/emojis (BeaconNamingRecord)
• Parse beacon pairing information (OwnedBeacons)
• Parse safe locations (SafeLocations)
• Parse beacon location history (BeaconEstimatedLocation)
• Parse shared beacons (SharedBeacons & Owner Sharing Circle)
• Decrypt Observations.db and associated -WAL
• Query Observations.db with two-stage analysis (DB only / DB+WAL)
• Process full iOS extraction zip files directly
• Export results to CSV and KML formats
• Associate beacon names with safe locations

Supports multiple iOS versions (15.3+)
Supports Graykey & Cellebrite extraction formats

For more information see the blog The Binary Hick (https://thebinaryhick.blog)

"""
        messagebox.showinfo("About", about_text)
        
    def _validate_inputs(self) -> bool:
        """
        Validate that required inputs are provided.
        
        Returns:
            True if inputs are valid, False otherwise
        """
        searchpartyd = self.searchpartyd_path.get()
        keychain = self.keychain_path.get()
        
        if not searchpartyd:
            messagebox.showerror("Missing Input", "Please select a searchpartyd folder or zip file.")
            return False
            
        # For zip files with embedded keychain, keychain may be included
        if not keychain or keychain == "[Included in UFED zip]":
            # Check if this is a zip file - we'll validate it has a keychain or needs one
            if self.using_zip:
                # Keychain may be extracted from zip, validation happens during analysis
                pass
            else:
                messagebox.showerror("Missing Input", "Please select a keychain plist file.")
                return False
            
        # Check if paths exist
        if not Path(searchpartyd).exists():
            messagebox.showerror("Invalid Path", f"File/folder not found:\n{searchpartyd}")
            return False
            
        # Only check keychain path if it's not coming from zip
        if keychain and keychain != "[Included in UFED zip]":
            if not Path(keychain).exists():
                messagebox.showerror("Invalid Path", f"Keychain file not found:\n{keychain}")
                return False
        
        # If it's a zip file, validate it can be processed
        if self.using_zip or is_zip_file(searchpartyd):
            try:
                # Use unified handler for validation
                temp_handler = UnifiedZipHandler(searchpartyd)
                info = temp_handler.get_info()
                
                if not info['has_searchpartyd']:
                    messagebox.showerror(
                        "Invalid Zip File",
                        f"Could not find com.apple.icloud.searchpartyd folder in {info['zip_type']} zip.\n\n"
                        "Please verify the zip file is a complete iOS extraction."
                    )
                    return False
                    
                # Warn if UFED zip has no keychain and user didn't provide one
                if info['zip_type'] == 'UFED' and not info['has_keychain']:
                    if not keychain or keychain == "[Included in UFED zip]":
                        messagebox.showwarning(
                            "Missing Keychain",
                            "UFED zip does not contain keychain file.\n\n"
                            "You will need to select a keychain file separately."
                        )
                        return False
                        
            except Exception as e:
                messagebox.showerror("Zip File Error", f"Error processing zip file:\n{str(e)}")
                return False
            
        return True
        
    def _start_analysis(self):
        """Start the forensics analysis."""
        if not self._validate_inputs():
            return
            
        # Disable start button, enable stop button
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.is_processing = True
        
        # Clear previous results
        self.beacon_store_key = None
        self.observations_key = None
        self.keychain_extractor = None
        self.wild_mode_records = []
        self.beacon_naming_records = []
        self.owned_beacon_records = []
        self.safe_location_records = []
        self.beacon_location_records = []
        self.shared_beacon_records = []
        self.owner_sharing_circle_records = []
        self.owner_peer_trust_records = []
        self.export_results_btn.config(state=tk.DISABLED)
        self.export_keys_btn.config(state=tk.DISABLED)
        
        # Run analysis in separate thread to keep GUI responsive
        analysis_thread = threading.Thread(target=self._run_analysis, daemon=True)
        analysis_thread.start()
        
    def _stop_analysis(self):
        """Stop the current analysis."""
        self.is_processing = False
        self.progress_var.set("Stopping...")
        self._log("Analysis stopped by user", "warning")
        # Cleanup zip extraction if used
        self._cleanup_zip()
        self._reset_buttons()
        
    def _reset_buttons(self):
        """Reset button states after analysis."""
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.progress_var.set("Ready")
        
    def _run_analysis(self):
        """
        Run the complete forensics analysis.
        This method runs in a separate thread.
        """
        actual_searchpartyd_path = None
        actual_keychain_path = None
        
        try:
            self._log("="*80, "header")
            self._log("Starting searchpartyd analysis", "header")
            self._log("="*80, "header")
            
            # If using a zip file, extract it first
            searchpartyd_input = self.searchpartyd_path.get()
            if self.using_zip or is_zip_file(searchpartyd_input):
                self._log("\n--- Extracting from Zip File ---", "header")
                self._log(f"Zip file: {searchpartyd_input}")
                
                try:
                    # Use unified handler for both UFED and Graykey zips
                    self.zip_handler = UnifiedZipHandler(searchpartyd_input)
                    
                    # Get info first
                    info = self.zip_handler.get_info()
                    self._log(f"Detected zip type: {info['zip_type']}")
                    
                    if info['filesystem_folders']:
                        self._log(f"Found {len(info['filesystem_folders'])} filesystem folder(s)")
                    
                    # Extract both searchpartyd and keychain (if present)
                    actual_searchpartyd_path, actual_keychain_path = self.zip_handler.extract_all()
                    
                    if not actual_searchpartyd_path:
                        self._log("✗ Could not find searchpartyd folder in zip", "error")
                        messagebox.showerror(
                            "Extraction Failed",
                            f"Could not find com.apple.icloud.searchpartyd folder in {info['zip_type']} zip.\n\n"
                            "Please verify the zip file is a complete iOS extraction."
                        )
                        self._reset_buttons()
                        return
                    
                    self._log(f"✓ Searchpartyd extracted to: {actual_searchpartyd_path}", "success")
                    
                    # Handle keychain (UFED only, but unified handler returns None for Graykey)
                    if actual_keychain_path:
                        self._log(f"✓ Keychain extracted to: {actual_keychain_path}", "success")
                        # Override the keychain path for extraction
                        self.keychain_path.set(actual_keychain_path)
                    elif info['zip_type'] == 'UFED':
                        self._log("⚠ No keychain found in UFED zip", "warning")
                        # Check if user provided a separate keychain
                        keychain_input = self.keychain_path.get()
                        if not keychain_input or keychain_input == "[Included in UFED zip]":
                            messagebox.showerror(
                                "Missing Keychain",
                                "No keychain found in UFED zip and no external keychain provided.\n\n"
                                "Please select a keychain file manually."
                            )
                            self._cleanup_zip()
                            self._reset_buttons()
                            return
                    
                except Exception as e:
                    self._log(f"✗ Extraction failed: {str(e)}", "error")
                    messagebox.showerror("Extraction Error", f"Failed to extract zip file:\n{str(e)}")
                    self._reset_buttons()
                    return
            else:
                actual_searchpartyd_path = searchpartyd_input
                self._log(f"\nUsing folder: {actual_searchpartyd_path}")
            
            # Step 1: Extract BeaconStore key
            if not self._extract_beacon_key():
                self._cleanup_zip()
                self._reset_buttons()
                return
                
            if not self.is_processing:
                self._cleanup_zip()
                self._reset_buttons()
                return
                
            # Step 2: Parse WildModeAssociationRecord
            self._parse_wild_mode_records(actual_searchpartyd_path)
            
            if not self.is_processing:
                self._cleanup_zip()
                self._reset_buttons()
                return
                
            # Step 3: Parse BeaconNamingRecord
            self._parse_beacon_naming_records(actual_searchpartyd_path)
            
            if not self.is_processing:
                self._cleanup_zip()
                self._reset_buttons()
                return
                
            # Step 4: Parse OwnedBeacons
            self._parse_owned_beacons(actual_searchpartyd_path)
            
            if not self.is_processing:
                self._cleanup_zip()
                self._reset_buttons()
                return
                
            # Step 5: Parse SafeLocations
            self._parse_safe_locations(actual_searchpartyd_path)
            
            if not self.is_processing:
                self._cleanup_zip()
                self._reset_buttons()
                return
            
            # Step 6: Parse BeaconEstimatedLocation
            self._parse_beacon_estimated_locations(actual_searchpartyd_path)
            
            if not self.is_processing:
                self._cleanup_zip()
                self._reset_buttons()
                return
            
            # Step 7: Parse SharedBeacons
            self._parse_shared_beacons(actual_searchpartyd_path)
            
            if not self.is_processing:
                self._cleanup_zip()
                self._reset_buttons()
                return
            
            # Step 8: Parse OwnerSharingCircle
            self._parse_owner_sharing_circle(actual_searchpartyd_path)
            
            if not self.is_processing:
                self._cleanup_zip()
                self._reset_buttons()
                return
            
            # Step 9: Parse OwnerPeerTrust
            self._parse_owner_peer_trust(actual_searchpartyd_path)
            
            # Step 10: Enrich OwnerSharingCircle with beacon names
            if self.owner_sharing_circle_records and self.beacon_naming_records:
                self._enrich_sharing_circle_records()
            
            if not self.is_processing:
                self._cleanup_zip()
                self._reset_buttons()
                return
            
            # Step 11: Decrypt Observations.db
            self._decrypt_observations_db(actual_searchpartyd_path)
            
            # Step 12: Export decrypted plists (if enabled)
            if self.export_plists_var.get():
                self._export_decrypted_plists()
            
            # Analysis complete
            self._log("="*80, "header")
            self._log("Analysis Complete!", "success")
            self._log("="*80, "header")
            
            # Clean up zip extraction if used
            if self.zip_handler:
                self._log("\nCleaning up temporary files...")
                self._cleanup_zip()
                self._log("✓ Temporary files removed", "success")
            
            # Enable export button if we have results
            if (self.wild_mode_records or self.beacon_naming_records or 
                self.owned_beacon_records or self.safe_location_records or 
                self.beacon_location_records or self.shared_beacon_records or
                self.owner_sharing_circle_records or self.owner_peer_trust_records):
                self.export_results_btn.config(state=tk.NORMAL)
                self._log("\n✓ Export Results button is now enabled", "success")
            
            # Enable Query Observations button if we have a decrypted database
            if self.observations_db_decrypted and Path(self.observations_db_decrypted).exists():
                self.query_obs_btn.config(state=tk.NORMAL)
                self._log("✓ Query Observations button is now enabled", "success")
            
        except Exception as e:
            self._log(f"FATAL ERROR: {str(e)}", "error")
            messagebox.showerror("Analysis Error", f"An error occurred during analysis:\n{str(e)}")
            # Clean up on error too
            self._cleanup_zip()
            
        finally:
            self._reset_buttons()
    
    def _show_export_dialog(self):
        """Show export options dialog with scrollable content."""
        if not (self.wild_mode_records or self.beacon_naming_records or 
                self.owned_beacon_records or self.safe_location_records or 
                self.beacon_location_records or self.shared_beacon_records or
                self.owner_sharing_circle_records or self.owner_peer_trust_records):
            messagebox.showinfo("No Data", "No parsed records available to export.\nRun analysis first.")
            return
        
        # Create export dialog window
        export_window = tk.Toplevel(self.root)
        export_window.title("Export Results")
        export_window.geometry("520x600")  # Initial size - window is now resizable
        export_window.minsize(450, 400)  # Minimum size to keep buttons visible
        export_window.resizable(True, True)  # Allow resizing
        
        # Center the window
        export_window.transient(self.root)
        export_window.grab_set()
        
        # Configure grid weights for resizing
        export_window.columnconfigure(0, weight=1)
        export_window.rowconfigure(0, weight=1)
        
        # Outer frame to hold canvas and scrollbar
        outer_frame = ttk.Frame(export_window)
        outer_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        outer_frame.columnconfigure(0, weight=1)
        outer_frame.rowconfigure(0, weight=1)
        
        # Create canvas for scrolling
        canvas = tk.Canvas(outer_frame, highlightthickness=0)
        canvas.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(outer_frame, orient=tk.VERTICAL, command=canvas.yview)
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Main frame inside canvas
        main_frame = ttk.Frame(canvas, padding="15")
        canvas_window = canvas.create_window((0, 0), window=main_frame, anchor=tk.NW)
        
        # Configure main_frame columns
        main_frame.columnconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        # Function to update scroll region when frame changes size
        def configure_scroll_region(event):
            canvas.configure(scrollregion=canvas.bbox("all"))
        
        main_frame.bind("<Configure>", configure_scroll_region)
        
        # Function to resize canvas window when canvas changes size
        def configure_canvas_window(event):
            canvas.itemconfig(canvas_window, width=event.width)
        
        canvas.bind("<Configure>", configure_canvas_window)
        
        # Enable mouse wheel scrolling
        def on_mousewheel(event):
            # For Windows and Linux
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        
        def on_mousewheel_mac(event):
            # For macOS
            canvas.yview_scroll(int(-1 * event.delta), "units")
        
        # Bind mousewheel based on platform
        import sys
        if sys.platform == 'darwin':  # macOS
            canvas.bind_all("<MouseWheel>", on_mousewheel_mac)
        else:  # Windows and Linux
            canvas.bind_all("<MouseWheel>", on_mousewheel)
            # Linux also uses Button-4 and Button-5 for scrolling
            canvas.bind_all("<Button-4>", lambda e: canvas.yview_scroll(-1, "units"))
            canvas.bind_all("<Button-5>", lambda e: canvas.yview_scroll(1, "units"))
        
        # Unbind mousewheel when window closes to prevent errors
        def on_close():
            canvas.unbind_all("<MouseWheel>")
            if sys.platform != 'darwin':
                canvas.unbind_all("<Button-4>")
                canvas.unbind_all("<Button-5>")
            export_window.destroy()
        
        export_window.protocol("WM_DELETE_WINDOW", on_close)
        
        # Title
        title_label = ttk.Label(main_frame, text="Export Parsed Records", font=("TkDefaultFont", 12, "bold"))
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 15))
        
        # WildMode section
        wild_frame = ttk.LabelFrame(main_frame, text="WildMode Records (Unwanted Trackers)", padding="10")
        wild_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        wild_count_label = ttk.Label(wild_frame, text=f"Records: {len(self.wild_mode_records)}")
        wild_count_label.grid(row=0, column=0, sticky=tk.W)
        
        if self.wild_mode_records:
            wild_csv_btn = ttk.Button(wild_frame, text="Export to CSV", 
                                     command=lambda: self._export_wild_mode_csv())
            wild_csv_btn.grid(row=1, column=0, pady=5, padx=5)
            
            wild_kml_btn = ttk.Button(wild_frame, text="Export to KML", 
                                     command=lambda: self._export_wild_mode_kml())
            wild_kml_btn.grid(row=1, column=1, pady=5, padx=5)
        else:
            no_data_label = ttk.Label(wild_frame, text="No records available", foreground="gray")
            no_data_label.grid(row=1, column=0, sticky=tk.W)
        
        # BeaconNaming section
        naming_frame = ttk.LabelFrame(main_frame, text="BeaconNaming Records (Custom Names)", padding="10")
        naming_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        naming_count_label = ttk.Label(naming_frame, text=f"Records: {len(self.beacon_naming_records)}")
        naming_count_label.grid(row=0, column=0, sticky=tk.W)
        
        if self.beacon_naming_records:
            naming_csv_btn = ttk.Button(naming_frame, text="Export to CSV", 
                                        command=lambda: self._export_naming_csv())
            naming_csv_btn.grid(row=1, column=0, pady=5)
        else:
            no_data_label = ttk.Label(naming_frame, text="No records available", foreground="gray")
            no_data_label.grid(row=1, column=0, sticky=tk.W)
        
        # OwnedBeacons section
        owned_frame = ttk.LabelFrame(main_frame, text="OwnedBeacons Records (Paired Devices)", padding="10")
        owned_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        owned_count_label = ttk.Label(owned_frame, text=f"Records: {len(self.owned_beacon_records)}")
        owned_count_label.grid(row=0, column=0, sticky=tk.W)
        
        if self.owned_beacon_records:
            owned_csv_btn = ttk.Button(owned_frame, text="Export to CSV", 
                                       command=lambda: self._export_owned_csv())
            owned_csv_btn.grid(row=1, column=0, pady=5)
        else:
            no_data_label = ttk.Label(owned_frame, text="No records available", foreground="gray")
            no_data_label.grid(row=1, column=0, sticky=tk.W)
        
        # SafeLocations section
        safe_frame = ttk.LabelFrame(main_frame, text="SafeLocations Records (Safe Locations)", padding="10")
        safe_frame.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        safe_count_label = ttk.Label(safe_frame, text=f"Records: {len(self.safe_location_records)}")
        safe_count_label.grid(row=0, column=0, sticky=tk.W)
        
        if self.safe_location_records:
            safe_csv_btn = ttk.Button(safe_frame, text="Export to CSV", 
                                     command=lambda: self._export_safe_csv())
            safe_csv_btn.grid(row=1, column=0, pady=5, padx=5)
            
            safe_kml_btn = ttk.Button(safe_frame, text="Export to KML", 
                                     command=lambda: self._export_safe_kml())
            safe_kml_btn.grid(row=1, column=1, pady=5, padx=5)
        else:
            no_data_label = ttk.Label(safe_frame, text="No records available", foreground="gray")
            no_data_label.grid(row=1, column=0, sticky=tk.W)
        
        # BeaconEstimatedLocation section
        location_frame = ttk.LabelFrame(main_frame, text="BeaconEstimatedLocation Records (Beacon Locations)", padding="10")
        location_frame.grid(row=5, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        location_count_label = ttk.Label(location_frame, text=f"Records: {len(self.beacon_location_records)}")
        location_count_label.grid(row=0, column=0, sticky=tk.W)
        
        if self.beacon_location_records:
            location_csv_btn = ttk.Button(location_frame, text="Export to CSV", 
                                         command=lambda: self._export_location_csv())
            location_csv_btn.grid(row=1, column=0, pady=5, padx=5)
            
            location_kml_btn = ttk.Button(location_frame, text="Export to KML", 
                                         command=lambda: self._export_location_kml())
            location_kml_btn.grid(row=1, column=1, pady=5, padx=5)
        else:
            no_data_label = ttk.Label(location_frame, text="No records available", foreground="gray")
            no_data_label.grid(row=1, column=0, sticky=tk.W)
        
        # SharedBeacons section
        shared_frame = ttk.LabelFrame(main_frame, text="SharedBeacons Records (Shared With Me)", padding="10")
        shared_frame.grid(row=6, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        shared_count_label = ttk.Label(shared_frame, text=f"Records: {len(self.shared_beacon_records)}")
        shared_count_label.grid(row=0, column=0, sticky=tk.W)
        
        if self.shared_beacon_records:
            shared_csv_btn = ttk.Button(shared_frame, text="Export to CSV", 
                                        command=lambda: self._export_shared_csv())
            shared_csv_btn.grid(row=1, column=0, pady=5)
        else:
            no_data_label = ttk.Label(shared_frame, text="No records available", foreground="gray")
            no_data_label.grid(row=1, column=0, sticky=tk.W)
        
        # OwnerSharingCircle section
        owner_sharing_frame = ttk.LabelFrame(main_frame, text="OwnerSharingCircle Records (Shared By Me)", padding="10")
        owner_sharing_frame.grid(row=7, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        owner_sharing_count_label = ttk.Label(owner_sharing_frame, text=f"Records: {len(self.owner_sharing_circle_records)}")
        owner_sharing_count_label.grid(row=0, column=0, sticky=tk.W)
        
        if self.owner_sharing_circle_records:
            owner_sharing_csv_btn = ttk.Button(owner_sharing_frame, text="Export to CSV", 
                                              command=lambda: self._export_owner_sharing_csv())
            owner_sharing_csv_btn.grid(row=1, column=0, pady=5)
        else:
            no_data_label = ttk.Label(owner_sharing_frame, text="No records available", foreground="gray")
            no_data_label.grid(row=1, column=0, sticky=tk.W)
        
        # OwnerPeerTrust section
        owner_peer_frame = ttk.LabelFrame(main_frame, text="OwnerPeerTrust Records (People Shared With)", padding="10")
        owner_peer_frame.grid(row=8, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        owner_peer_count_label = ttk.Label(owner_peer_frame, text=f"Records: {len(self.owner_peer_trust_records)}")
        owner_peer_count_label.grid(row=0, column=0, sticky=tk.W)
        
        if self.owner_peer_trust_records:
            owner_peer_csv_btn = ttk.Button(owner_peer_frame, text="Export to CSV", 
                                           command=lambda: self._export_owner_peer_csv())
            owner_peer_csv_btn.grid(row=1, column=0, pady=5)
        else:
            no_data_label = ttk.Label(owner_peer_frame, text="No records available", foreground="gray")
            no_data_label.grid(row=1, column=0, sticky=tk.W)
        
        # Close button
        close_btn = ttk.Button(main_frame, text="Close", command=on_close, width=15)
        close_btn.grid(row=9, column=0, columnspan=2, pady=(20, 0))
    
    def _export_wild_mode_csv(self):
        """Export WildMode records to individual CSV files (one per UUID)."""
        directory = filedialog.askdirectory(
            title="Select Directory for Individual CSV Files",
            initialdir=Path.home()
        )
        
        if directory:
            try:
                parser = WildModeParser(self.beacon_store_key)
                count = parser.export_all_records_to_individual_csvs(self.wild_mode_records, directory)
                messagebox.showinfo(
                    "Export Success", 
                    f"Created {count} individual CSV files in:\n{directory}\n\n"
                    "Each .record file has its own CSV for easier analysis."
                )
                self._log(f"✓ WildMode records exported to {count} CSV files in: {directory}", "success")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export:\n{str(e)}")
                self._log(f"✗ Export failed: {str(e)}", "error")
    
    def _export_wild_mode_kml(self):
        """Export WildMode locations to individual KML files."""
        directory = filedialog.askdirectory(
            title="Select Directory for Individual KML Files",
            initialdir=Path.home()
        )
        
        if directory:
            try:
                parser = WildModeParser(self.beacon_store_key)
                count = parser.export_all_records_to_individual_kmls(self.wild_mode_records, directory)
                messagebox.showinfo(
                    "Export Success", 
                    f"Created {count} individual KML files in:\n{directory}\n\n"
                    "Each .record file has its own KML for easier analysis."
                )
                self._log(f"✓ WildMode locations exported to {count} KML files in: {directory}", "success")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export:\n{str(e)}")
                self._log(f"✗ Export failed: {str(e)}", "error")
    
    def _export_naming_csv(self):
        """Export BeaconNaming records to CSV."""
        file = filedialog.asksaveasfilename(
            title="Export BeaconNaming Records to CSV",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile=f"beacon_naming_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        )
        
        if file:
            try:
                parser = BeaconNamingParser(self.beacon_store_key)
                if parser.export_to_csv(self.beacon_naming_records, file):
                    messagebox.showinfo("Export Success", f"BeaconNaming records exported to:\n{file}")
                    self._log(f"✓ BeaconNaming records exported to CSV: {file}", "success")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export:\n{str(e)}")
                self._log(f"✗ Export failed: {str(e)}", "error")
    
    def _export_owned_csv(self):
        """Export OwnedBeacons records to CSV."""
        file = filedialog.asksaveasfilename(
            title="Export OwnedBeacons Records to CSV",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile=f"owned_beacons_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        )
        
        if file:
            try:
                parser = OwnedBeaconsParser(self.beacon_store_key)
                if parser.export_to_csv(self.owned_beacon_records, file):
                    messagebox.showinfo("Export Success", f"OwnedBeacons records exported to:\n{file}")
                    self._log(f"✓ OwnedBeacons records exported to CSV: {file}", "success")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export:\n{str(e)}")
                self._log(f"✗ Export failed: {str(e)}", "error")
    
    def _export_safe_csv(self):
        """Export SafeLocations records to CSV."""
        file = filedialog.asksaveasfilename(
            title="Export SafeLocations Records to CSV",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile=f"safe_locations_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        )
        
        if file:
            try:
                parser = SafeLocationsParser(self.beacon_store_key)
                if parser.export_to_csv(self.safe_location_records, file):
                    messagebox.showinfo("Export Success", f"SafeLocations records exported to:\n{file}")
                    self._log(f"✓ SafeLocations records exported to CSV: {file}", "success")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export:\n{str(e)}")
                self._log(f"✗ Export failed: {str(e)}", "error")
    
    def _export_safe_kml(self):
        """Export SafeLocations to KML."""
        file = filedialog.asksaveasfilename(
            title="Export SafeLocations to KML",
            defaultextension=".kml",
            filetypes=[("KML files", "*.kml"), ("All files", "*.*")],
            initialfile=f"safe_locations_{datetime.now().strftime('%Y%m%d_%H%M%S')}.kml"
        )
        
        if file:
            try:
                parser = SafeLocationsParser(self.beacon_store_key)
                if parser.export_to_kml(self.safe_location_records, file, "Safe Locations"):
                    messagebox.showinfo("Export Success", f"SafeLocations exported to:\n{file}")
                    self._log(f"✓ SafeLocations exported to KML: {file}", "success")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export:\n{str(e)}")
                self._log(f"✗ Export failed: {str(e)}", "error")
    
    def _export_location_csv(self):
        """Export BeaconEstimatedLocation records to CSV."""
        file = filedialog.asksaveasfilename(
            title="Export BeaconEstimatedLocation Records to CSV",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile=f"beacon_locations_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        )
        
        if file:
            try:
                parser = BeaconEstimatedLocationParser(self.beacon_store_key)
                if parser.export_to_csv(self.beacon_location_records, file):
                    messagebox.showinfo("Export Success", f"BeaconEstimatedLocation records exported to:\n{file}")
                    self._log(f"✓ BeaconEstimatedLocation records exported to CSV: {file}", "success")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export:\n{str(e)}")
                self._log(f"✗ Export failed: {str(e)}", "error")
    
    def _export_location_kml(self):
        """Export BeaconEstimatedLocation to individual KML files."""
        directory = filedialog.askdirectory(
            title="Select Directory for Individual KML Files",
            initialdir=Path.home()
        )
        
        if directory:
            try:
                parser = BeaconEstimatedLocationParser(self.beacon_store_key)
                count = parser.export_to_kml(self.beacon_location_records, directory)
                messagebox.showinfo(
                    "Export Success", 
                    f"Created {count} individual KML files in:\n{directory}\n\n"
                    "Each beacon UUID has its own KML file for easier analysis."
                )
                self._log(f"✓ BeaconEstimatedLocation exported to {count} KML files in: {directory}", "success")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export:\n{str(e)}")
                self._log(f"✗ Export failed: {str(e)}", "error")
    
    def _export_shared_csv(self):
        """Export SharedBeacons records to CSV."""
        file = filedialog.asksaveasfilename(
            title="Export SharedBeacons Records to CSV",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile=f"shared_beacons_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        )
        
        if file:
            try:
                parser = SharedBeaconsParser(self.beacon_store_key)
                if parser.export_to_csv(self.shared_beacon_records, file):
                    messagebox.showinfo("Export Success", f"SharedBeacons records exported to:\n{file}")
                    self._log(f"✓ SharedBeacons records exported to CSV: {file}", "success")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export:\n{str(e)}")
                self._log(f"✗ Export failed: {str(e)}", "error")
    
    def _export_owner_sharing_csv(self):
        """Export OwnerSharingCircle records to CSV."""
        file = filedialog.asksaveasfilename(
            title="Export OwnerSharingCircle Records to CSV",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile=f"owner_sharing_circle_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        )
        
        if file:
            try:
                parser = OwnerSharingCircleParser(self.beacon_store_key)
                if parser.export_to_csv(self.owner_sharing_circle_records, file):
                    messagebox.showinfo("Export Success", f"OwnerSharingCircle records exported to:\n{file}")
                    self._log(f"✓ OwnerSharingCircle records exported to CSV: {file}", "success")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export:\n{str(e)}")
                self._log(f"✗ Export failed: {str(e)}", "error")
    
    def _export_owner_peer_csv(self):
        """Export OwnerPeerTrust records to CSV."""
        file = filedialog.asksaveasfilename(
            title="Export OwnerPeerTrust Records to CSV",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile=f"owner_peer_trust_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        )
        
        if file:
            try:
                parser = OwnerPeerTrustParser(self.beacon_store_key)
                if parser.export_to_csv(self.owner_peer_trust_records, file):
                    messagebox.showinfo("Export Success", f"OwnerPeerTrust records exported to:\n{file}")
                    self._log(f"✓ OwnerPeerTrust records exported to CSV: {file}", "success")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export:\n{str(e)}")
                self._log(f"✗ Export failed: {str(e)}", "error")
            
    def _extract_beacon_key(self) -> bool:
        """
        Extract the BeaconStore and Observations keys from keychain.
        Supports both UFED (encrypted) and Graykey (plain) formats.
        
        Returns:
            True if successful, False otherwise
        """
        self.progress_var.set("Extracting encryption keys...")
        self._log("\n--- Step 1: Extract Encryption Keys ---", "header")
        
        keychain_path = self.keychain_path.get()
        self._log(f"Loading keychain: {keychain_path}")
        
        try:
            # First, try the simple KeychainParser (for Graykey and simple UFED formats)
            parser = KeychainParser(keychain_path)
            keys = parser.parse()
            
            source_type = parser.get_source_type()
            self._log(f"Detected keychain format: {source_type}")
            self._log(f"Found {len(keys)} keys in keychain")
            
            # List available keys for debugging
            available = parser.list_available_keys()
            if available:
                self._log(f"  Available services: {', '.join(available)}")
            
            self.beacon_store_key = parser.get_beacon_store_key()
            
            # Also try to get Observations key from the simple parser first
            # This works for Graykey format where keys are already decrypted
            self.observations_key = parser.get_observations_key()
            
            # If simple parser didn't find the BeaconStore key, try the complex UFED extractor
            if not self.beacon_store_key and source_type == 'UFED':
                self._log("Trying complex UFED keychain extraction...")
                extractor = iOSKeychainExtractor(keychain_path)
                keys = extractor.parse()
                self.beacon_store_key = extractor.get_beacon_store_key()
                
                # Also get Observations key from complex extractor if not found earlier
                if not self.observations_key:
                    self.observations_key = extractor.get_key_by_service('Observations')
                self.keychain_extractor = extractor  # Save for later use
                
                if self.beacon_store_key:
                    self._log(f"Found {len(keys)} keys using complex UFED extraction")
            
            # If we still don't have Observations key but simple parser found BeaconStore,
            # try the complex extractor as a fallback for Observations
            if self.beacon_store_key and not self.observations_key:
                try:
                    extractor = iOSKeychainExtractor(keychain_path)
                    extractor.parse()
                    self.observations_key = extractor.get_key_by_service('Observations')
                    self.keychain_extractor = extractor
                except:
                    # If extractor fails, that's OK - Observations is optional
                    pass
            
            if self.beacon_store_key:
                self._log("✓ BeaconStore key extracted successfully!", "success")
                self._log(f"  Format: {source_type}")
                self._log(f"  Key (hex): {self.beacon_store_key.hex()}")
                self._log(f"  Key length: {len(self.beacon_store_key)} bytes")
                
                # Log Observations key status
                if self.observations_key:
                    self._log("✓ Observations key extracted successfully!", "success")
                    self._log(f"  Key (hex): {self.observations_key.hex()}")
                    self._log(f"  Key length: {len(self.observations_key)} bytes")
                else:
                    self._log("⚠ Observations key not found (database decryption unavailable)", "warning")
                
                # Enable the Export Keys button now that we have at least one key
                self.export_keys_btn.config(state=tk.NORMAL)
                self._log("✓ Export Keys button is now enabled", "success")
                
                return True
            else:
                self._log("✗ BeaconStore key not found in keychain", "error")
                available = ', '.join(parser.list_available_keys())
                self._log(f"  Available keys: {available}")
                messagebox.showerror(
                    "Key Not Found",
                    "BeaconStore key not found in keychain.\n\n"
                    "Please verify:\n"
                    "• The keychain file is from the same iOS extraction\n"
                    "• The keychain file format is supported\n"
                    "• Supported formats: UFED, Graykey (iOS 15.3+)"
                )
                return False
                
        except Exception as e:
            self._log(f"✗ Failed to extract key: {str(e)}", "error")
            messagebox.showerror("Extraction Error", f"Failed to extract keys:\n{str(e)}")
            return False
            
    def _parse_wild_mode_records(self, searchpartyd_path):
        """Parse WildModeAssociationRecord files."""
        self.progress_var.set("Parsing WildMode records...")
        self._log("\n--- Step 2: Parse WildModeAssociationRecord ---", "header")
        
        wild_mode_path = Path(searchpartyd_path) / "WildModeAssociationRecord"
        
        if not wild_mode_path.exists():
            self._log(f"⚠ WildModeAssociationRecord folder not found", "warning")
            return
            
        self._log(f"Parsing directory: {wild_mode_path}")
        
        try:
            parser = WildModeParser(self.beacon_store_key)
            self.wild_mode_records = parser.parse_directory(str(wild_mode_path))
            
            self._log(f"✓ Successfully parsed {len(self.wild_mode_records)} WildMode records", "success")
            
            # Display summary of results
            if self.wild_mode_records:
                self._log("\nWildMode Records Summary:")
                for i, record in enumerate(self.wild_mode_records, 1):
                    self._log(f"  Record {i}:")
                    self._log(f"    UUID: {record.uuid}")
                    if record.manufacturer:
                        self._log(f"    Manufacturer: {record.manufacturer}")
                    if record.tracker_uuid:
                        self._log(f"    Tracker UUID: {record.tracker_uuid}")
                    self._log(f"    Locations: {len(record.locations)}")
                    self._log(f"    MAC Addresses: {len(record.mac_addresses)}")
                    
        except Exception as e:
            self._log(f"✗ Failed to parse WildMode records: {str(e)}", "error")
            
    def _parse_beacon_naming_records(self, searchpartyd_path):
        """Parse BeaconNamingRecord files."""
        self.progress_var.set("Parsing BeaconNaming records...")
        self._log("\n--- Step 3: Parse BeaconNamingRecord ---", "header")
        
        naming_path = Path(searchpartyd_path) / "BeaconNamingRecord"
        
        if not naming_path.exists():
            self._log(f"⚠ BeaconNamingRecord folder not found", "warning")
            return
            
        self._log(f"Parsing directory: {naming_path}")
        
        try:
            parser = BeaconNamingParser(self.beacon_store_key)
            self.beacon_naming_records = parser.parse_directory(str(naming_path))
            
            self._log(f"✓ Successfully parsed {len(self.beacon_naming_records)} BeaconNaming records", "success")
            
            # Display summary of results
            if self.beacon_naming_records:
                self._log("\nBeaconNaming Records Summary:")
                for i, record in enumerate(self.beacon_naming_records, 1):
                    self._log(f"  Record {i}:")
                    self._log(f"    Record UUID: {record.uuid}")
                    if record.name:
                        self._log(f"    Name: {record.name}")
                    if record.emoji:
                        self._log(f"    Emoji: {record.emoji}")
                    if record.associated_beacon:
                        self._log(f"    Associated Beacon: {record.associated_beacon}")
                        
        except Exception as e:
            self._log(f"✗ Failed to parse BeaconNaming records: {str(e)}", "error")
            
    def _parse_owned_beacons(self, searchpartyd_path):
        """Parse OwnedBeacons files."""
        self.progress_var.set("Parsing OwnedBeacons records...")
        self._log("\n--- Step 4: Parse OwnedBeacons ---", "header")
        
        owned_path = Path(searchpartyd_path) / "OwnedBeacons"
        
        if not owned_path.exists():
            self._log(f"⚠ OwnedBeacons folder not found", "warning")
            return
            
        self._log(f"Parsing directory: {owned_path}")
        
        try:
            parser = OwnedBeaconsParser(self.beacon_store_key)
            self.owned_beacon_records = parser.parse_directory(str(owned_path))
            
            self._log(f"✓ Successfully parsed {len(self.owned_beacon_records)} OwnedBeacon records", "success")
            
            # Enrich OwnedBeacons with custom names and emojis from BeaconNamingRecords
            if self.owned_beacon_records and self.beacon_naming_records:
                self._log("Enriching OwnedBeacons with custom names and emojis...")
                parser.enrich_with_naming_records(self.owned_beacon_records, self.beacon_naming_records)
                named_count = sum(1 for r in self.owned_beacon_records if r.custom_name)
                self._log(f"✓ Added custom names to {named_count} beacons", "success")
            
            # Display summary of results
            if self.owned_beacon_records:
                self._log("\nOwnedBeacons Records Summary:")
                for i, record in enumerate(self.owned_beacon_records, 1):
                    self._log(f"  Record {i}:")
                    self._log(f"    Identifier: {record.identifier}")
                    if record.custom_name:
                        name_display = record.custom_name
                        if record.emoji:
                            name_display = f"{record.emoji} {record.custom_name}"
                        self._log(f"    Name: {name_display}")
                    if record.pairing_date:
                        self._log(f"    Pairing Date: {record.pairing_date}")
                    if record.stable_identifier:
                        self._log(f"    Stable Identifier: {record.stable_identifier}")
                        
        except Exception as e:
            self._log(f"✗ Failed to parse OwnedBeacons records: {str(e)}", "error")
    
    def _parse_safe_locations(self, searchpartyd_path):
        """Parse SafeLocations files."""
        self.progress_var.set("Parsing SafeLocations records...")
        self._log("\n--- Step 5: Parse SafeLocations ---", "header")
        
        safe_path = Path(searchpartyd_path) / "SafeLocations"
        
        if not safe_path.exists():
            self._log(f"⚠ SafeLocations folder not found", "warning")
            return
            
        self._log(f"Parsing directory: {safe_path}")
        
        try:
            parser = SafeLocationsParser(self.beacon_store_key)
            self.safe_location_records = parser.parse_directory(str(safe_path))
            
            # Associate beacon names with the safe locations
            if self.safe_location_records and (self.beacon_naming_records or self.owned_beacon_records):
                self._log("Associating beacon names with safe locations...")
                parser.associate_beacon_names(
                    self.safe_location_records,
                    self.beacon_naming_records,
                    self.owned_beacon_records
                )
            
            self._log(f"✓ Successfully parsed {len(self.safe_location_records)} SafeLocation records", "success")
            
            # Display summary of results
            if self.safe_location_records:
                self._log("\nSafeLocations Records Summary:")
                for i, record in enumerate(self.safe_location_records, 1):
                    self._log(f"  Record {i}:")
                    self._log(f"    UUID: {record.uuid}")
                    self._log(f"    Name: {record.name or '(Unnamed)'}")
                    self._log(f"    Location: {record.latitude}, {record.longitude}")
                    if record.radius:
                        self._log(f"    Radius: {record.radius} meters")
                    self._log(f"    Associated Beacons: {len(record.associated_beacons)}")
                    if record.timestamps:
                        self._log(f"    Timestamps: {len(record.timestamps)}")
                        
        except Exception as e:
            self._log(f"✗ Failed to parse SafeLocations records: {str(e)}", "error")
    
    def _parse_beacon_estimated_locations(self, searchpartyd_path):
        """Parse BeaconEstimatedLocation files."""
        self.progress_var.set("Parsing BeaconEstimatedLocation records...")
        self._log("\n--- Step 6: Parse BeaconEstimatedLocation ---", "header")
        
        location_path = Path(searchpartyd_path) / "BeaconEstimatedLocation"
        
        if not location_path.exists():
            self._log(f"⚠ BeaconEstimatedLocation folder not found", "warning")
            return
            
        self._log(f"Parsing directory: {location_path}")
        
        try:
            parser = BeaconEstimatedLocationParser(self.beacon_store_key)
            self.beacon_location_records = parser.parse_directory(str(location_path))
            
            # Associate beacon names with the location records
            if self.beacon_location_records and self.beacon_naming_records:
                self._log("Associating beacon names with location records...")
                parser.associate_beacon_names(
                    self.beacon_location_records,
                    self.beacon_naming_records
                )
            
            self._log(f"✓ Successfully parsed {len(self.beacon_location_records)} BeaconEstimatedLocation records", "success")
            
            # Display summary of results
            if self.beacon_location_records:
                # Group by beacon UUID for summary
                beacon_groups = {}
                for record in self.beacon_location_records:
                    if record.beacon_uuid not in beacon_groups:
                        beacon_groups[record.beacon_uuid] = []
                    beacon_groups[record.beacon_uuid].append(record)
                
                self._log("\nBeaconEstimatedLocation Records Summary:")
                self._log(f"  Total location records: {len(self.beacon_location_records)}")
                self._log(f"  Unique beacons with locations: {len(beacon_groups)}")
                self._log("\n  Breakdown by beacon:")
                for beacon_uuid, records in beacon_groups.items():
                    beacon_name = records[0].beacon_name if records[0].beacon_name else "(No Name)"
                    self._log(f"    {beacon_name} ({beacon_uuid}): {len(records)} locations")
                        
        except Exception as e:
            self._log(f"✗ Failed to parse BeaconEstimatedLocation records: {str(e)}", "error")
    
    def _parse_shared_beacons(self, searchpartyd_path):
        """Parse SharedBeacons files."""
        self.progress_var.set("Parsing SharedBeacons records...")
        self._log("\n--- Step 7: Parse SharedBeacons ---", "header")
        
        shared_path = Path(searchpartyd_path) / "SharedBeacons"
        
        if not shared_path.exists():
            self._log(f"⚠ SharedBeacons folder not found", "warning")
            return
            
        self._log(f"Parsing directory: {shared_path}")
        
        try:
            parser = SharedBeaconsParser(self.beacon_store_key)
            self.shared_beacon_records = parser.parse_directory(str(shared_path))
            
            # Associate beacon names with the shared beacons
            if self.shared_beacon_records and self.beacon_naming_records:
                self._log("Associating beacon names with shared beacons...")
                parser.associate_beacon_names(
                    self.shared_beacon_records,
                    self.beacon_naming_records
                )
            
            self._log(f"✓ Successfully parsed {len(self.shared_beacon_records)} SharedBeacon records", "success")
            
            # Display summary of results
            if self.shared_beacon_records:
                self._log("\nSharedBeacons Records Summary:")
                for i, record in enumerate(self.shared_beacon_records, 1):
                    self._log(f"  Record {i}:")
                    self._log(f"    Record UUID: {record.uuid}")
                    self._log(f"    Beacon Identifier: {record.identifier or 'Unknown'}")
                    self._log(f"    Beacon Name: {record.beacon_name or '(Not assigned)'}")
                    self._log(f"    Shared By: {record.destination or 'Unknown'}")
                    if record.share_date:
                        self._log(f"    Share Date: {record.share_date}")
                        
        except Exception as e:
            self._log(f"✗ Failed to parse SharedBeacons records: {str(e)}", "error")
    
    def _parse_owner_sharing_circle(self, searchpartyd_path):
        """Parse OwnerSharingCircle files."""
        self.progress_var.set("Parsing OwnerSharingCircle records...")
        self._log("\n--- Step 8: Parse OwnerSharingCircle ---", "header")
        
        sharing_path = Path(searchpartyd_path) / "OwnerSharingCircle"
        
        if not sharing_path.exists():
            self._log(f"⚠ OwnerSharingCircle folder not found", "warning")
            return
            
        self._log(f"Parsing directory: {sharing_path}")
        
        try:
            parser = OwnerSharingCircleParser(self.beacon_store_key)
            self.owner_sharing_circle_records = parser.parse_directory(str(sharing_path))
            
            self._log(f"✓ Successfully parsed {len(self.owner_sharing_circle_records)} OwnerSharingCircle records", "success")
            
            # Display summary of results
            if self.owner_sharing_circle_records:
                self._log("\nOwnerSharingCircle Records Summary:")
                for i, record in enumerate(self.owner_sharing_circle_records, 1):
                    self._log(f"  Record {i}:")
                    self._log(f"    Record ID: {record.identifier}")
                    self._log(f"    Beacon ID: {record.beacon_identifier}")
                    self._log(f"    Members: {len(record.members)}")
                    self._log(f"    Acceptance State: {record.acceptance_state}")
                        
        except Exception as e:
            self._log(f"✗ Failed to parse OwnerSharingCircle records: {str(e)}", "error")
    
    def _parse_owner_peer_trust(self, searchpartyd_path):
        """Parse OwnerPeerTrust files."""
        self.progress_var.set("Parsing OwnerPeerTrust records...")
        self._log("\n--- Step 9: Parse OwnerPeerTrust ---", "header")
        
        peer_path = Path(searchpartyd_path) / "OwnerPeerTrust"
        
        if not peer_path.exists():
            self._log(f"⚠ OwnerPeerTrust folder not found", "warning")
            return
            
        self._log(f"Parsing directory: {peer_path}")
        
        try:
            parser = OwnerPeerTrustParser(self.beacon_store_key)
            self.owner_peer_trust_records = parser.parse_directory(str(peer_path))
            
            self._log(f"✓ Successfully parsed {len(self.owner_peer_trust_records)} OwnerPeerTrust records", "success")

            # Enrich with beacon names from OwnerSharingCircle and BeaconNamingRecord
            if self.owner_peer_trust_records and self.owner_sharing_circle_records and self.beacon_naming_records:
                self._log("Enriching OwnerPeerTrust with beacon names...")
                enriched_records = parser.enrich_with_beacon_names(
                    self.owner_peer_trust_records,
                    self.owner_sharing_circle_records,
                    self.beacon_naming_records
                )
                self.owner_peer_trust_records = enriched_records
                
                # Count how many were enriched
                enriched_count = sum(1 for record in self.owner_peer_trust_records if record.beacon_names)
                total_beacons = sum(len(record.beacon_names) for record in self.owner_peer_trust_records)
                
                self._log(f"✓ Enriched {enriched_count} peer records with {total_beacons} beacon names", "success")

            # Display summary of results
            if self.owner_peer_trust_records:
                self._log("\nOwnerPeerTrust Records Summary:")
                for i, record in enumerate(self.owner_peer_trust_records, 1):
                    self._log(f"  Record {i}:")
                    self._log(f"    Record ID: {record.identifier}")
                    self._log(f"    Display Identifier: {record.display_identifier or 'Unknown'}")
                    self._log(f"    Destination: {record.destination or 'Unknown'}")
                    if record.sharing_timestamp:
                        self._log(f"    Shared: {record.sharing_timestamp}")

                    if record.beacon_names:
                        self._log(f"    Shared Beacons: {len(record.beacon_names)}")
                        for name, emoji in record.beacon_names:
                            emoji_str = f" {emoji}" if emoji else ""
                            self._log(f"      - {name}{emoji_str}")
                        
        except Exception as e:
            self._log(f"✗ Failed to parse OwnerPeerTrust records: {str(e)}", "error")
    
    def _enrich_sharing_circle_records(self):
        """Enrich OwnerSharingCircle records with beacon names from BeaconNamingRecords."""
        self.progress_var.set("Enriching sharing circle records...")
        self._log("\n--- Step 10: Enrich Sharing Circle with Beacon Names ---", "header")
        
        try:
            parser = OwnerSharingCircleParser(self.beacon_store_key)
            parser.enrich_with_naming_records(
                self.owner_sharing_circle_records,
                self.beacon_naming_records
            )
            
            # Count how many were enriched
            enriched_count = sum(1 for record in self.owner_sharing_circle_records 
                               if record.beacon_name is not None)
            
            self._log(f"✓ Enriched {enriched_count} of {len(self.owner_sharing_circle_records)} records with beacon names", "success")
            
            # Display enriched results
            if enriched_count > 0:
                self._log("\nEnriched Records:")
                for i, record in enumerate(self.owner_sharing_circle_records, 1):
                    if record.beacon_name:
                        emoji_str = f" {record.beacon_emoji}" if record.beacon_emoji else ""
                        self._log(f"  Record {i}: {record.beacon_name}{emoji_str}")
                        
        except Exception as e:
            self._log(f"✗ Failed to enrich sharing circle records: {str(e)}", "error")
    
    def _decrypt_observations_db(self, searchpartyd_path):
        """
        Decrypt Observations.db and its WAL file (Step 11).
        
        The Observations.db is typically located in the parent directory of searchpartyd folder:
        /var/mobile/Library/com.apple.icloud.searchpartyd/ (records)
        /var/mobile/Library/Observations.db (database)
        
        IMPORTANT: This method decrypts both files WITHOUT opening them with SQLite,
        which would cause SQLite to automatically checkpoint (commit) the WAL data.
        The original decrypted files are preserved separately for later two-stage analysis.
        
        Args:
            searchpartyd_path: Path to the searchpartyd folder
        """
        self.progress_var.set("Decrypting Observations.db...")
        self._log("\n--- Step 11: Decrypt Observations.db ---", "header")
        
        # Check if we have the Observations key
        if not self.observations_key:
            self._log("⚠ Observations key not found in keychain - skipping database decryption", "warning")
            self._log("  The Observations.db contains device observation records with locations")
            return
        
        # Look for Observations.db in the parent directory of searchpartyd
        searchpartyd_path = Path(searchpartyd_path)
        parent_dir = searchpartyd_path.parent
        
        self._log(f"  Searchpartyd path: {searchpartyd_path}")
        self._log(f"  Parent directory: {parent_dir}")
        
        # Possible locations for Observations.db
        possible_paths = [
            parent_dir / "Observations.db",
            searchpartyd_path / "Observations.db",  # Sometimes it's in the same folder
            parent_dir.parent / "Observations.db",  # Go up one more level
        ]
        
        self._log(f"  Searching for Observations.db in {len(possible_paths)} locations:")
        for i, path in enumerate(possible_paths, 1):
            self._log(f"    Location {i}: {path} - {'EXISTS' if path.exists() else 'not found'}")
        
        obs_db_path = None
        for path in possible_paths:
            if path.exists():
                obs_db_path = path
                break
        
        if not obs_db_path:
            self._log("⚠ Observations.db not found in extraction", "warning")
            self._log(f"  Searched in: {parent_dir}")
            self._log("  This database is optional - continuing with other records")
            return
        
        self._log(f"Found Observations.db: {obs_db_path}")
        
        # Check for WAL file
        wal_path = Path(str(obs_db_path) + "-wal")
        self._log(f"  Looking for WAL file at: {wal_path}")
        wal_exists = wal_path.exists()
        if wal_exists:
            wal_size = wal_path.stat().st_size
            self._log(f"✓ Found WAL file: {wal_path} ({wal_size:,} bytes)")
        else:
            self._log(f"  WAL file not found")
        
        try:
            # Create decryptor
            decryptor = ObservationsDecryptor(self.observations_key)
            
            # Create dedicated output folder in current directory
            output_dir = Path.cwd() / "decrypted_observations"
            output_dir.mkdir(parents=True, exist_ok=True)
            self._log(f"\nDecrypting to: {output_dir}")
            
            # Decrypt database first
            output_db = output_dir / "Observations_decrypted.db"
            self._log("Decrypting main database...")
            decryptor.decrypt_database(str(obs_db_path), str(output_db))
            
            # Verify the file was created and has valid SQLite magic header
            # IMPORTANT: We verify by reading raw bytes, NOT by opening with SQLite
            # Opening with SQLite would cause it to auto-checkpoint any WAL file
            if output_db.exists():
                with open(str(output_db), 'rb') as f:
                    header = f.read(16)
                if header == b'SQLite format 3\x00':
                    db_size = output_db.stat().st_size
                    self._log(f"✓ Database decrypted: {output_db.name} ({db_size:,} bytes)", "success")
                    self.observations_db_decrypted = str(output_db)
                else:
                    self._log(f"✗ Decryption produced invalid SQLite file", "error")
                    return
            else:
                self._log(f"✗ Database file not created", "error")
                return
            
            # Now decrypt WAL file if present
            # IMPORTANT: We do NOT open the database with SQLite at any point!
            # Opening it would cause SQLite to auto-checkpoint the WAL data.
            if wal_exists:
                output_wal = output_dir / "Observations_decrypted.db-wal"
                self._log("Decrypting WAL file...")
                try:
                    success, num_frames = decryptor.decrypt_wal(str(wal_path), str(output_wal))
                    if success and output_wal.exists():
                        wal_decrypted_size = output_wal.stat().st_size
                        self._log(f"✓ WAL decrypted: {output_wal.name} ({wal_decrypted_size:,} bytes, {num_frames} frames)", "success")
                        self.observations_wal_decrypted = str(output_wal)
                    else:
                        self._log(f"⚠ WAL decryption returned success={success}, but file may not exist", "warning")
                except Exception as wal_error:
                    self._log(f"✗ WAL decryption failed: {str(wal_error)}", "error")
                    self._log("  The main database was decrypted successfully", "warning")
            
            # Summary
            self._log("\n" + "="*60, "header")
            self._log("✓ Observations.db decryption complete!", "success")
            self._log("="*60, "header")
            self._log(f"  Database: {output_db.name}")
            if self.observations_wal_decrypted:
                self._log(f"  WAL file: {Path(self.observations_wal_decrypted).name}")
            
            self._log("\n  IMPORTANT: The decrypted files are preserved separately.")
            self._log("  The WAL has NOT been committed to the database.")
            self._log("  Use 'Query Observations...' button for two-stage analysis:")
            self._log("    Stage 1: Database only (without WAL)")
            self._log("    Stage 2: Database + WAL (more complete data)")
            
        except Exception as e:
            self._log(f"✗ Failed to decrypt Observations.db: {str(e)}", "error")
            self._log("  This is non-fatal - continuing with other records")
    
    def _export_decrypted_plists(self):
        """
        Export decrypted binary plist files from parsed records (Step 12).
        
        Creates a folder structure mirroring the original searchpartyd folder:
        decrypted_plists/
        ├── WildModeAssociationRecord/
        ├── BeaconNamingRecord/
        ├── OwnedBeacons/
        └── ... (other record types)
        
        Each plist file uses the same UUID as its source .record file.
        """
        self.progress_var.set("Exporting decrypted plists...")
        self._log("\n--- Step 12: Export Decrypted Plist Files ---", "header")
        
        try:
            # Create exporter (uses current working directory by default)
            exporter = PlistExporter()
            
            self._log(f"Output directory: {exporter.output_base_dir}")
            
            # Export all record types
            results = exporter.export_all_records(
                wild_mode_records=self.wild_mode_records,
                beacon_naming_records=self.beacon_naming_records,
                owned_beacon_records=self.owned_beacon_records,
                safe_location_records=self.safe_location_records,
                beacon_location_records=self.beacon_location_records,
                shared_beacon_records=self.shared_beacon_records,
                owner_sharing_circle_records=self.owner_sharing_circle_records,
                owner_peer_trust_records=self.owner_peer_trust_records
            )
            
            # Log results
            if results['total_exported'] > 0:
                self._log(f"✓ Exported {results['total_exported']} decrypted plist files", "success")
                
                # Show breakdown by type
                for record_type, type_results in results['record_types'].items():
                    if type_results['exported'] > 0:
                        self._log(f"  {record_type}: {type_results['exported']} files")
                
                self._log(f"\n  Output folder: {results['output_base_dir']}")
            else:
                self._log("⚠ No plist files exported (records may not have raw_data)", "warning")
            
            if results['total_failed'] > 0:
                self._log(f"⚠ Failed to export {results['total_failed']} files", "warning")
                
        except Exception as e:
            self._log(f"✗ Failed to export decrypted plists: {str(e)}", "error")
            self._log("  This is non-fatal - continuing with analysis")
    
    def _show_observations_query_dialog(self):
        """
        Show dialog for running SQLite queries on Observations.db with scrollable content.
        
        Provides two-stage analysis:
        1. Query database only (without WAL)
        2. Query database with WAL committed (more complete data)
        """
        if not self.observations_db_decrypted or not Path(self.observations_db_decrypted).exists():
            messagebox.showerror(
                "No Database",
                "Decrypted Observations.db not found.\n\n"
                "Please run analysis first to decrypt the database."
            )
            return
        
        # Create query dialog window
        query_window = tk.Toplevel(self.root)
        query_window.title("Query Observations.db")
        query_window.geometry("620x550")  # Initial size - window is now resizable
        query_window.minsize(500, 400)  # Minimum size to keep content visible
        query_window.resizable(True, True)  # Allow resizing
        
        # Center the window
        query_window.transient(self.root)
        query_window.grab_set()
        
        # Configure grid weights for resizing
        query_window.columnconfigure(0, weight=1)
        query_window.rowconfigure(0, weight=1)
        
        # Outer frame to hold canvas and scrollbar
        outer_frame = ttk.Frame(query_window)
        outer_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        outer_frame.columnconfigure(0, weight=1)
        outer_frame.rowconfigure(0, weight=1)
        
        # Create canvas for scrolling
        canvas = tk.Canvas(outer_frame, highlightthickness=0)
        canvas.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(outer_frame, orient=tk.VERTICAL, command=canvas.yview)
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Main frame inside canvas
        main_frame = ttk.Frame(canvas, padding="15")
        canvas_window = canvas.create_window((0, 0), window=main_frame, anchor=tk.NW)
        
        # Configure main_frame columns
        main_frame.columnconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        # Function to update scroll region when frame changes size
        def configure_scroll_region(event):
            canvas.configure(scrollregion=canvas.bbox("all"))
        
        main_frame.bind("<Configure>", configure_scroll_region)
        
        # Function to resize canvas window when canvas changes size
        def configure_canvas_window(event):
            canvas.itemconfig(canvas_window, width=event.width)
        
        canvas.bind("<Configure>", configure_canvas_window)
        
        # Enable mouse wheel scrolling
        def on_mousewheel(event):
            # For Windows and Linux
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        
        def on_mousewheel_mac(event):
            # For macOS
            canvas.yview_scroll(int(-1 * event.delta), "units")
        
        # Bind mousewheel based on platform
        import sys
        if sys.platform == 'darwin':  # macOS
            canvas.bind_all("<MouseWheel>", on_mousewheel_mac)
        else:  # Windows and Linux
            canvas.bind_all("<MouseWheel>", on_mousewheel)
            # Linux also uses Button-4 and Button-5 for scrolling
            canvas.bind_all("<Button-4>", lambda e: canvas.yview_scroll(-1, "units"))
            canvas.bind_all("<Button-5>", lambda e: canvas.yview_scroll(1, "units"))
        
        # Unbind mousewheel when window closes to prevent errors
        def on_close():
            canvas.unbind_all("<MouseWheel>")
            if sys.platform != 'darwin':
                canvas.unbind_all("<Button-4>")
                canvas.unbind_all("<Button-5>")
            query_window.destroy()
        
        query_window.protocol("WM_DELETE_WINDOW", on_close)
        
        # Title
        title_label = ttk.Label(
            main_frame, 
            text="Observations.db Query Tool", 
            font=("TkDefaultFont", 12, "bold")
        )
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 10))
        
        # Description
        desc_text = (
            "Query the decrypted Observations.db to extract FindMy device observation locations and advertisement payloads.\n\n"
            "Due to data volatility, the query is run twice:\n"
            "  Round 1: Query main database only (without WAL data)\n"
            "  Round 2: Query main database with WAL committed\n\n"
            "Output from both rounds is provided for comparions purposes and to provide the most data."
        )
        desc_label = ttk.Label(main_frame, text=desc_text, justify=tk.LEFT)
        desc_label.grid(row=1, column=0, columnspan=2, sticky=tk.W, pady=(0, 15))
        
        # Database info frame
        info_frame = ttk.LabelFrame(main_frame, text="Database Information", padding="10")
        info_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        # Show database path
        db_label = ttk.Label(info_frame, text=f"Database: {Path(self.observations_db_decrypted).name}")
        db_label.grid(row=0, column=0, sticky=tk.W)
        
        # Show WAL status
        wal_status = "Available" if self.observations_wal_decrypted and Path(self.observations_wal_decrypted).exists() else "Not available"
        wal_color = "green" if wal_status == "Available" else "orange"
        wal_label = ttk.Label(info_frame, text=f"WAL file: {wal_status}")
        wal_label.grid(row=1, column=0, sticky=tk.W)
        
        # Get table info
        try:
            handler = ObservationsQueryHandler(
                self.observations_db_decrypted,
                self.observations_wal_decrypted
            )
            table_info = handler.get_table_info()
            
            tables_text = "Tables: " + ", ".join([f"{t}({c})" for t, c in table_info.items()])
            tables_label = ttk.Label(info_frame, text=tables_text, wraplength=450)
            tables_label.grid(row=2, column=0, sticky=tk.W)
        except Exception as e:
            tables_label = ttk.Label(info_frame, text=f"Error reading tables: {str(e)}")
            tables_label.grid(row=2, column=0, sticky=tk.W)
        
        # Output directory info (fixed folder in working directory)
        output_frame = ttk.LabelFrame(main_frame, text="Output Directory", padding="10")
        output_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=10)
        output_frame.columnconfigure(0, weight=1)
        
        # Fixed output directory - always use observations_db_query_output folder
        fixed_output_dir = Path.cwd() / "observations_db_query_output"
        output_dir_label = ttk.Label(
            output_frame, 
            text=f"CSV and KML files will be saved to:\n{fixed_output_dir}",
            wraplength=450
        )
        output_dir_label.grid(row=0, column=0, sticky=tk.W)
        
        # Options frame
        options_frame = ttk.LabelFrame(main_frame, text="Query Options", padding="10")
        options_frame.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        # Extended query option
        extended_query_var = tk.BooleanVar(value=False)
        extended_check = ttk.Checkbutton(
            options_frame,
            text="Use extended query (includes Advertisement ID and Sequence Number)",
            variable=extended_query_var
        )
        extended_check.grid(row=0, column=0, sticky=tk.W)
        
        # Export KML option
        export_kml_var = tk.BooleanVar(value=True)
        kml_check = ttk.Checkbutton(
            options_frame,
            text="Export GPS coordinates to KML files",
            variable=export_kml_var
        )
        kml_check.grid(row=1, column=0, sticky=tk.W)
        
        # Results frame (initially empty, will show after query)
        results_frame = ttk.LabelFrame(main_frame, text="Query Results", padding="10")
        results_frame.grid(row=5, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=10)
        
        results_text = tk.StringVar(value="Click 'Run Query' to execute the two-stage analysis.")
        results_label = ttk.Label(results_frame, textvariable=results_text, wraplength=450)
        results_label.grid(row=0, column=0, sticky=tk.W)
        
        # Button frame
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=6, column=0, columnspan=2, pady=(15, 0))
        
        def run_query():
            """Execute the two-stage query."""
            # Use fixed output directory
            output_dir = Path.cwd() / "observations_db_query_output"
            output_dir.mkdir(parents=True, exist_ok=True)
            
            # Disable button during processing
            run_btn.config(state=tk.DISABLED)
            results_text.set("Running query... Please wait.")
            query_window.update()
            
            # Run in thread to keep GUI responsive
            def do_query():
                try:
                    self._log("\n" + "="*80, "header")
                    self._log("Running Observations.db Query (On-Demand)", "header")
                    self._log("="*80, "header")
                    
                    handler = ObservationsQueryHandler(
                        self.observations_db_decrypted,
                        self.observations_wal_decrypted
                    )
                    
                    use_extended = extended_query_var.get()
                    
                    self._log(f"\nOutput directory: {output_dir}")
                    self._log(f"Extended query: {use_extended}")
                    self._log(f"Export KML: {export_kml_var.get()}")
                    
                    # Run the full two-stage analysis
                    self._log("\nExecuting two-stage analysis...")
                    self._log("  Note: Original decrypted files are preserved")
                    results = handler.run_full_analysis(
                        str(output_dir), 
                        use_extended,
                        export_kml=export_kml_var.get()
                    )
                    
                    # Build results summary
                    summary_lines = []
                    
                    for stage in results['stages']:
                        self._log(f"\n--- {stage['name']} ---", "header")
                        if stage.get('success'):
                            self._log(f"✓ Records found: {stage['record_count']}", "success")
                            if 'additional_from_wal' in stage:
                                self._log(f"  Additional from WAL: {stage['additional_from_wal']}")
                            self._log(f"  Locations with GPS: {stage.get('location_count', 0)}")
                            self._log(f"  CSV: {Path(stage.get('csv_path', '')).name}")
                            if export_kml_var.get() and stage.get('kml_path'):
                                self._log(f"  KML: {Path(stage['kml_path']).name}")
                            
                            summary_lines.append(
                                f"{stage['name']}: {stage['record_count']} records, "
                                f"{stage.get('location_count', 0)} locations"
                            )
                        else:
                            error = stage.get('error', 'Unknown error')
                            if stage.get('skipped'):
                                self._log(f"⚠ Skipped: {error}", "warning")
                                summary_lines.append(f"{stage['name']}: Skipped (no WAL)")
                            else:
                                self._log(f"✗ Failed: {error}", "error")
                                summary_lines.append(f"{stage['name']}: Failed")
                    
                    # Log completion
                    self._log("\n" + "="*80, "header")
                    self._log("Query Complete!", "success")
                    self._log("="*80, "header")
                    self._log(f"\nOutput files saved to: {output_dir}")
                    self._log("\nFiles created:")
                    for stage in results['stages']:
                        if stage.get('success'):
                            self._log(f"  ✓ {Path(stage.get('csv_path', '')).name}")
                            if export_kml_var.get() and stage.get('kml_path'):
                                self._log(f"  ✓ {Path(stage['kml_path']).name}")
                    
                    # Also note preserved working database if available
                    for stage in results['stages']:
                        if stage.get('work_db_path'):
                            self._log(f"\nPreserved for further analysis:")
                            self._log(f"  ✓ {Path(stage['work_db_path']).name} (DB with WAL committed)")
                            break
                    
                    # Update GUI
                    summary = "\n".join(summary_lines)
                    summary += f"\n\nFiles saved to: {output_dir}"
                    query_window.after(0, lambda: results_text.set(summary))
                    query_window.after(0, lambda: run_btn.config(state=tk.NORMAL))
                    
                    # Show success message
                    query_window.after(0, lambda: messagebox.showinfo(
                        "Query Complete",
                        f"Two-stage analysis complete!\n\n{summary}\n\n"
                        "Check the Analysis Log for details."
                    ))
                    
                except Exception as e:
                    self._log(f"\n✗ Query failed: {str(e)}", "error")
                    import traceback
                    self._log(f"  Traceback: {traceback.format_exc()}", "error")
                    
                    query_window.after(0, lambda: results_text.set(f"Error: {str(e)}"))
                    query_window.after(0, lambda: run_btn.config(state=tk.NORMAL))
                    query_window.after(0, lambda: messagebox.showerror(
                        "Query Error",
                        f"Query failed:\n{str(e)}\n\nCheck the Analysis Log for details."
                    ))
            
            # Run in thread
            query_thread = threading.Thread(target=do_query, daemon=True)
            query_thread.start()
        
        run_btn = ttk.Button(button_frame, text="Run Query", command=run_query, width=15)
        run_btn.grid(row=0, column=0, padx=10)
        
        close_btn = ttk.Button(button_frame, text="Close", command=on_close, width=15)
        close_btn.grid(row=0, column=1, padx=10)
        
        # Note about preserved files
        note_label = ttk.Label(
            main_frame,
            text="Note: Decrypted database and WAL files are in 'decrypted_observations' folder.\n"
                 "Query results (CSV/KML) are saved to 'observations_db_query_output' folder.",
            font=("TkDefaultFont", 8, "italic"),
            foreground="gray"
        )
        note_label.grid(row=7, column=0, columnspan=2, pady=(10, 0))


def main():
    """Main entry point for the GUI application."""
    root = tk.Tk()
    
    # Set icon if available (optional)
    # root.iconbitmap('icon.ico')
    
    app = SearchpartydGUI(root)
    
    # Register cleanup handler for when GUI closes
    def on_closing():
        """Clean up temporary files when GUI closes."""
        try:
            # Clean up query handler temp files
            ObservationsQueryHandler.cleanup_temp_files()
        except Exception:
            pass  # Ignore cleanup errors
        root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    
    # Add initial welcome message
    app._log("="*80, "header")
    app._log("Welcome to Lost Apples", "header")
    app._log("="*80, "header")
    app._log("\nTo begin analysis:")
    app._log("1. Select the searchpartyd folder OR a full iOS extraction zip file")
    app._log("   - Folder: Direct path to com.apple.icloud.searchpartyd")
    app._log("   - Zip: Full iOS extraction (will auto-find searchpartyd folder)")
    app._log("2. Select the keychain.plist file from the same extraction (not necessary for Premium/Inseyets UFED exttractions)")
    app._log("3. Click 'Start Analysis' to process all records")
    app._log("4. Use 'Export Results' button to save parsed data")
    app._log("5. Use the 'Query Observations...' button to run a SQLite query against the decrypted Observations.db and export results")
    app._log("Note: Individual parsers can still be run from command line.")
    
    # Start the GUI event loop
    root.mainloop()


if __name__ == "__main__":
    main()
