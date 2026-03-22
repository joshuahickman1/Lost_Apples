"""
keys_file_parser.py — Parser for Apple Find My .keys files
Part of the Lost Apples forensic analysis tool.

.keys files are precomputed rolling advertisement key caches stored under:
    com.apple.icloud.searchpartyd/Keys/<beacon_UUID>/Primary/
    com.apple.icloud.searchpartyd/Keys/<beacon_UUID>/Secondary/
    com.apple.icloud.searchpartyd/Keys/<beacon_UUID>/Primary-Advertisements/

Each file holds P-224 key pairs at 15 min/key:
  Primary/                — separated-mode (lost mode) keys; up to 28 days (~2,689 entries)
  Secondary/              — near-owner mode keys; ~5 days (~510 entries)
  Primary-Advertisements/ — short rolling advertisement batch; ~24 hrs (~97 entries)

Reference: Heinrich et al. "Who Can Find My Devices?" (PETS 2021)
"""

from __future__ import annotations

import csv
import hashlib
import base64
import struct
import plistlib
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Dict, List, Optional, Tuple

# ─────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────

KEYS_MAGIC          = b'KEY'
KEYS_VERSION        = 0x02
HEADER_SIZE         = 32       # bytes
ENTRY_SIZE_EXPECTED = 207      # bytes  (read from header, but validated here)
SK_I_SIZE           = 32       # bytes  AES-256 symmetric rolling key
D_I_SIZE            = 28       # bytes  P-224 private key
P_I_SIZE            = 28       # bytes  P-224 public key (X coord)
D_I_PREFIX          = bytes([0x02, 0x04])  # P-224 private key always starts here

# Offsets within a single entry
OFF_SK = 0
OFF_D  = 32
OFF_P  = 60
# bytes 88-89 are variable data (not a fixed marker — confirmed from Secondary file)
OFF_BPLIST = 90   # 117-byte embedded bplist; stored but not further parsed


# ─────────────────────────────────────────────────────────────
# Data Classes
# ─────────────────────────────────────────────────────────────

@dataclass
class KeyEntry:
    """One 15-minute advertisement key window for a beacon."""

    key_id:      int    # Sequential key ID (e.g. 41848 for Primary, 1 for Secondary)
    sk_i:        bytes  # 32-byte AES-256 symmetric rolling key
    d_i:         bytes  # 28-byte P-224 private key (can decrypt location reports)
    p_i:         bytes  # 28-byte P-224 public key  (broadcast over BLE)
    report_id:   str    # base64(SHA-256(p_i)) — Apple server lookup ID
    key_type:    str    = "primary"    # "primary", "secondary", or "primary_advertisements"
    beacon_uuid: str    = ""           # parent folder UUID
    beacon_name: Optional[str] = None  # enriched from BeaconNamingRecord
    beacon_emoji: Optional[str] = None # enriched from BeaconNamingRecord

    # ── derived convenience properties ──────────────────────

    @property
    def sk_i_hex(self) -> str:
        return self.sk_i.hex()

    @property
    def d_i_hex(self) -> str:
        return self.d_i.hex()

    @property
    def p_i_hex(self) -> str:
        return self.p_i.hex()

    def __str__(self) -> str:
        name_str = ""
        if self.beacon_name:
            emoji = f" {self.beacon_emoji}" if self.beacon_emoji else ""
            name_str = f"  Beacon:    {self.beacon_name}{emoji}\n"
        return (
            f"Key ID:    {self.key_id}  [{self.key_type}]\n"
            f"{name_str}"
            f"  UUID:      {self.beacon_uuid}\n"
            f"  SK_i:      {self.sk_i_hex}\n"
            f"  d_i:       {self.d_i_hex}\n"
            f"  p_i:       {self.p_i_hex}\n"
            f"  Report ID: {self.report_id}"
        )


# ─────────────────────────────────────────────────────────────
# Single-File Parser
# ─────────────────────────────────────────────────────────────

class KeysFileParser:
    """
    Parse a single .keys file.

    Usage:
        parser = KeysFileParser("path/to/41848-44536.keys",
                                beacon_uuid="6C5D11C8-...",
                                key_type="primary")
        entries = parser.parse()
    """

    def __init__(
        self,
        keys_file_path: str,
        beacon_uuid: str = "",
        key_type: str = "primary",
    ):
        self.path        = Path(keys_file_path)
        self.beacon_uuid = beacon_uuid
        self.key_type    = key_type.lower()

        # Populated by parse()
        self._entries:    List[KeyEntry] = []
        self._start_id:   int = 0
        self._end_id:     int = 0
        self._entry_size: int = 0
        self._parsed:     bool = False

    # ── public interface ─────────────────────────────────────

    def parse(self) -> List[KeyEntry]:
        """
        Parse all key entries from the .keys file.

        Returns a list of KeyEntry objects sorted by key_id.
        Raises ValueError if the file fails validation.
        """
        raw = self.path.read_bytes()
        self._validate_and_read_header(raw)
        self._entries = self._read_entries(raw)
        self._parsed = True
        return self._entries

    def get_report_ids(self) -> List[str]:
        """Return every base64 SHA-256(p_i) report ID in key_id order."""
        self._ensure_parsed()
        return [e.report_id for e in self._entries]

    def get_entry_by_key_id(self, key_id: int) -> Optional[KeyEntry]:
        """Look up a single entry by its key ID. Returns None if not found."""
        self._ensure_parsed()
        idx = key_id - self._start_id
        if 0 <= idx < len(self._entries):
            return self._entries[idx]
        return None

    def enrich_with_beacon_name(self, name: str, emoji: str = None):
        """
        Apply a beacon name and optional emoji to every entry in this file.
        Call this after matching the beacon_uuid against BeaconNamingRecord data.
        """
        self._ensure_parsed()
        for entry in self._entries:
            entry.beacon_name  = name
            entry.beacon_emoji = emoji

    def to_csv_rows(self) -> List[Dict]:
        """Return all entries as a list of dicts ready for csv.DictWriter."""
        self._ensure_parsed()
        rows = []
        for e in self._entries:
            rows.append({
                "Beacon_Name":      e.beacon_name  or "",
                "Beacon_UUID":      e.beacon_uuid,
                "Key_Type":         e.key_type,
                "Beacon_Emoji":     e.beacon_emoji or "",
                "Key_ID":           e.key_id,
                "Symmetric_Key_Hex": e.sk_i_hex,
                "Private_Key_Hex":   e.d_i_hex,
                "Public_Key_Hex":    e.p_i_hex,
                "Report_ID_base64":  e.report_id,
            })
        return rows

    def to_kml(self) -> str:
        """
        Placeholder — location data comes from decrypted Apple server reports,
        not from this file.  The report_id values are the lookup keys needed
        to retrieve those reports from acsnservice/fetch.
        """
        return (
            "<!-- KML export not applicable for .keys files.\n"
            "     Use Report_ID_base64 values to fetch encrypted location\n"
            "     reports from Apple's acsnservice/fetch endpoint.\n"
            "     Those reports can then be decrypted with the matching d_i key. -->"
        )

    # ── summary helpers ──────────────────────────────────────

    @property
    def start_id(self) -> int:
        self._ensure_parsed()
        return self._start_id

    @property
    def end_id(self) -> int:
        self._ensure_parsed()
        return self._end_id

    @property
    def num_entries(self) -> int:
        self._ensure_parsed()
        return len(self._entries)

    @property
    def time_coverage_hours(self) -> float:
        """Approximate time window in hours (15 min per key)."""
        self._ensure_parsed()
        return self.num_entries * 15 / 60

    # ── private helpers ──────────────────────────────────────

    def _validate_and_read_header(self, raw: bytes) -> None:
        """Validate magic/version/size and populate header fields."""
        if len(raw) < HEADER_SIZE:
            raise ValueError(
                f"{self.path.name}: file too small ({len(raw)} bytes); "
                f"expected at least {HEADER_SIZE}"
            )

        magic = raw[0:3]
        if magic != KEYS_MAGIC:
            raise ValueError(
                f"{self.path.name}: bad magic {magic!r}; expected b'KEY'"
            )

        version = raw[3]
        if version != KEYS_VERSION:
            raise ValueError(
                f"{self.path.name}: unexpected version 0x{version:02X}; "
                f"expected 0x{KEYS_VERSION:02X}"
            )

        self._entry_size = struct.unpack_from("<I", raw, 4)[0]
        self._start_id   = struct.unpack_from("<I", raw, 8)[0]
        self._end_id     = struct.unpack_from("<I", raw, 12)[0]

        if self._entry_size == 0:
            raise ValueError(f"{self.path.name}: entry_size is 0 in header")

        if self._end_id < self._start_id:
            raise ValueError(
                f"{self.path.name}: end_id ({self._end_id}) < "
                f"start_id ({self._start_id})"
            )

        num_entries   = self._end_id - self._start_id + 1
        expected_size = HEADER_SIZE + num_entries * self._entry_size

        if len(raw) != expected_size:
            raise ValueError(
                f"{self.path.name}: file size mismatch — "
                f"got {len(raw)}, expected {expected_size} "
                f"({num_entries} entries × {self._entry_size} bytes + {HEADER_SIZE})"
            )

    def _read_entries(self, raw: bytes) -> List[KeyEntry]:
        """Parse every entry from the file body."""
        num_entries = self._end_id - self._start_id + 1
        entries = []

        for i in range(num_entries):
            key_id = self._start_id + i
            offset = HEADER_SIZE + i * self._entry_size

            sk_i = raw[offset + OFF_SK : offset + OFF_SK + SK_I_SIZE]
            d_i  = raw[offset + OFF_D  : offset + OFF_D  + D_I_SIZE]
            p_i  = raw[offset + OFF_P  : offset + OFF_P  + P_I_SIZE]

            # Sanity check — every valid P-224 private key starts 0x02 0x04
            if d_i[:2] != D_I_PREFIX:
                # Non-fatal: log and keep parsing; forensic data is still usable
                print(
                    f"  [WARNING] {self.path.name} entry {i} (key_id={key_id}): "
                    f"d_i does not start with 0x0204 ({d_i[:2].hex()}) — "
                    f"entry may be corrupt"
                )

            report_id = base64.b64encode(hashlib.sha256(p_i).digest()).decode()

            entries.append(KeyEntry(
                key_id      = key_id,
                sk_i        = sk_i,
                d_i         = d_i,
                p_i         = p_i,
                report_id   = report_id,
                key_type    = self.key_type,
                beacon_uuid = self.beacon_uuid,
            ))

        return entries

    def _ensure_parsed(self) -> None:
        if not self._parsed:
            self.parse()


# ─────────────────────────────────────────────────────────────
# Directory-Level Parser
# ─────────────────────────────────────────────────────────────

class KeysDirectoryParser:
    """
    Scan a Keys/ folder for all .keys files under every beacon UUID,
    handling Primary, Secondary, and Primary-Advertisements subfolders.

    Expected structure:
        Keys/
        └── <beacon_UUID>/
            ├── Primary/                   ← separated-mode, ~28 days
            │   └── <startID>-<endID>.keys
            ├── Secondary/                 ← near-owner mode, ~5 days
            │   └── <startID>-<endID>.keys
            └── Primary-Advertisements/   ← rolling active batch, ~24 hrs
                └── <startID>-<endID>.keys

    Usage:
        dir_parser = KeysDirectoryParser("path/to/Keys/")
        all_entries = dir_parser.parse_all()          # flat list
        by_uuid     = dir_parser.entries_by_uuid()    # dict keyed by UUID
    """

    def __init__(self, keys_folder_path: str):
        self.keys_folder = Path(keys_folder_path)
        self._all_entries: List[KeyEntry] = []
        self._errors:      List[str]      = []
        self._parsed       = False

        # Summary info keyed by (uuid, key_type)
        self._file_summary: List[Dict] = []

    # ── public interface ─────────────────────────────────────

    def parse_all(self) -> List[KeyEntry]:
        """
        Parse every .keys file found under the Keys/ folder.
        Non-fatal: individual file errors are logged and skipped.
        Returns a flat list of all KeyEntry objects.
        """
        if not self.keys_folder.exists():
            raise FileNotFoundError(
                f"Keys folder not found: {self.keys_folder}"
            )

        self._all_entries.clear()
        self._errors.clear()
        self._file_summary.clear()

        for uuid_dir in sorted(self.keys_folder.iterdir()):
            if not uuid_dir.is_dir():
                continue
            beacon_uuid = uuid_dir.name.upper()

            for subfolder_name in ("Primary", "Secondary", "Primary-Advertisements"):
                subfolder = uuid_dir / subfolder_name
                if not subfolder.exists():
                    continue

                # Normalise to a clean key_type string:
                # "Primary" -> "primary", "Secondary" -> "secondary",
                # "Primary-Advertisements" -> "primary_advertisements"
                key_type = subfolder_name.lower().replace("-", "_")

                for keys_file in sorted(subfolder.glob("*.keys")):
                    self._parse_one_file(keys_file, beacon_uuid, key_type)

        self._parsed = True
        return self._all_entries

    def entries_by_uuid(self) -> Dict[str, List[KeyEntry]]:
        """
        Return a dict mapping beacon_uuid → list of KeyEntry.
        Includes entries from all subfolder types if present.
        """
        self._ensure_parsed()
        result: Dict[str, List[KeyEntry]] = {}
        for e in self._all_entries:
            result.setdefault(e.beacon_uuid, []).append(e)
        return result

    def entries_by_uuid_and_type(
        self,
    ) -> Dict[Tuple[str, str], List[KeyEntry]]:
        """
        Return a dict mapping (beacon_uuid, key_type) → list of KeyEntry.
        Useful when you need Primary, Secondary, and Primary-Advertisements
        treated separately.
        """
        self._ensure_parsed()
        result: Dict[Tuple[str, str], List[KeyEntry]] = {}
        for e in self._all_entries:
            result.setdefault((e.beacon_uuid, e.key_type), []).append(e)
        return result

    def enrich_with_beacon_names(
        self,
        naming_records: list,
    ) -> None:
        """
        Apply beacon names from a list of BeaconNamingRecord objects to all
        entries.  Matches on beacon_uuid (case-insensitive).

        naming_records should be the output of BeaconNamingParser.parse_directory().
        Each record is expected to have:
            .associated_beacon : str   (the UUID)
            .name              : str
            .emoji             : str | None
        """
        self._ensure_parsed()
        lookup: Dict[str, Tuple[str, Optional[str]]] = {}
        for rec in naming_records:
            uuid_key = getattr(rec, "associated_beacon", "").upper()
            if uuid_key:
                lookup[uuid_key] = (
                    getattr(rec, "name",  ""),
                    getattr(rec, "emoji", None),
                )

        enriched = 0
        for entry in self._all_entries:
            if entry.beacon_uuid in lookup:
                entry.beacon_name, entry.beacon_emoji = lookup[entry.beacon_uuid]
                enriched += 1

        print(f"  Keys enrichment: applied names to {enriched} key entries "
              f"across {len(lookup)} beacon UUID(s)")

    def get_all_report_ids(self) -> List[str]:
        """Flat list of every report ID across all files and types."""
        self._ensure_parsed()
        return [e.report_id for e in self._all_entries]

    def to_csv_rows(self) -> List[Dict]:
        """All entries as CSV-ready dicts."""
        self._ensure_parsed()
        rows = []
        for e in self._all_entries:
            rows.append({
                "Beacon_Name":      e.beacon_name  or "",
                "Beacon_UUID":      e.beacon_uuid,
                "Key_Type":         e.key_type,
                "Beacon_Emoji":     e.beacon_emoji or "",
                "Key_ID":           e.key_id,
                "Symmetric_Key_Hex": e.sk_i_hex,
                "Private_Key_Hex":   e.d_i_hex,
                "Public_Key_Hex":    e.p_i_hex,
                "Report_ID_base64":  e.report_id,
            })
        return rows

    @property
    def file_summary(self) -> List[Dict]:
        """
        Per-file summary for GUI display.
        Each dict has: uuid, key_type, filename, start_id, end_id,
                       num_entries, time_coverage_hours, error.
        """
        self._ensure_parsed()
        return self._file_summary

    @property
    def errors(self) -> List[str]:
        """List of non-fatal error messages from parse_all()."""
        return self._errors

    # ── private helpers ──────────────────────────────────────

    def _parse_one_file(
        self,
        keys_file: Path,
        beacon_uuid: str,
        key_type: str,
    ) -> None:
        summary: Dict = {
            "uuid":                beacon_uuid,
            "key_type":            key_type,
            "filename":            keys_file.name,
            "start_id":            None,
            "end_id":              None,
            "num_entries":         0,
            "time_coverage_hours": 0.0,
            "error":               None,
        }

        try:
            parser  = KeysFileParser(str(keys_file), beacon_uuid, key_type)
            entries = parser.parse()
            self._all_entries.extend(entries)

            summary["start_id"]           = parser.start_id
            summary["end_id"]             = parser.end_id
            summary["num_entries"]        = parser.num_entries
            summary["time_coverage_hours"] = parser.time_coverage_hours

        except Exception as exc:  # noqa: BLE001
            msg = f"{keys_file}: {exc}"
            self._errors.append(msg)
            summary["error"] = str(exc)
            print(f"  [WARNING] {msg}")

        self._file_summary.append(summary)

    def _ensure_parsed(self) -> None:
        if not self._parsed:
            self.parse_all()


# ─────────────────────────────────────────────────────────────
# GUI Log Formatting Helper
# ─────────────────────────────────────────────────────────────

def _display_key_type(key_type: str) -> str:
    """Convert internal key_type string to a human-readable folder name."""
    return {
        "primary":                "Primary",
        "secondary":              "Secondary",
        "primary_advertisements": "Primary-Advertisements",
    }.get(key_type, key_type.replace("_", "-").title())


def format_gui_log(dir_parser: KeysDirectoryParser) -> List[Tuple[str, str]]:
    """
    Build a list of (message, level) tuples for the Lost Apples GUI log panel.

    level is one of: "" (info), "success", "warning", "error"

    Example usage in searchpartyd_gui.py:
        from src.keys_file_parser import KeysDirectoryParser, format_gui_log
        dir_parser = KeysDirectoryParser(keys_folder_path)
        dir_parser.parse_all()
        for msg, level in format_gui_log(dir_parser):
            self._log(msg, level)
    """
    lines: List[Tuple[str, str]] = []

    for s in dir_parser.file_summary:
        lines.append((f"Keys folder: {s['uuid']} / {_display_key_type(s['key_type'])}", ""))

        if s["error"]:
            lines.append((f"  Error: {s['error']}", "error"))
            continue

        lines.append((f"  File:          {s['filename']}", ""))
        lines.append((f"  Key ID range:  {s['start_id']} → {s['end_id']}", ""))
        lines.append((f"  Total keys:    {s['num_entries']:,}", ""))
        lines.append(
            (
                f"  Time coverage: ~{s['time_coverage_hours']:.1f} hrs "
                f"({s['time_coverage_hours']/24:.1f} days at 15 min/key)",
                "",
            )
        )

        # Show two sample report IDs inline (non-sensitive — these are
        # SHA-256 hashes of public keys, not the keys themselves)
        entries = [
            e for e in dir_parser._all_entries
            if e.beacon_uuid == s["uuid"] and e.key_type == s["key_type"]
        ]
        if entries:
            lines.append(("  Sample Report IDs:", ""))
            for e in entries[:2]:
                name_tag = f" [{e.beacon_name}]" if e.beacon_name else ""
                lines.append((f"    Key {e.key_id}{name_tag}: {e.report_id}", ""))
            if len(entries) > 2:
                lines.append((f"    ... ({len(entries) - 2:,} more)", ""))

    total = sum(s["num_entries"] for s in dir_parser.file_summary if not s["error"])
    if total:
        lines.append((f"✓ Key cache parsed: {total:,} key pairs total", "success"))
    else:
        lines.append(("No key entries parsed", "warning"))

    for err in dir_parser.errors:
        lines.append((f"[WARNING] {err}", "warning"))

    return lines


# ─────────────────────────────────────────────────────────────
# CLI Entry Point
# ─────────────────────────────────────────────────────────────

def _cli_main() -> None:
    """
    Standalone CLI usage:

        python keys_file_parser.py path/to/Keys/
        python keys_file_parser.py path/to/41848-44536.keys --uuid 6C5D11C8-...
    """
    import argparse

    ap = argparse.ArgumentParser(
        description="Parse Apple Find My .keys advertisement key cache files"
    )
    ap.add_argument("path", help="Path to a .keys file or a Keys/ directory")
    ap.add_argument(
        "--uuid",
        default="",
        help="Beacon UUID (optional; inferred from directory name if omitted)",
    )
    ap.add_argument(
        "--csv",
        metavar="OUTPUT.csv",
        help="Export all entries to a CSV file",
    )
    ap.add_argument(
        "--show-keys",
        action="store_true",
        help="Print SK_i / d_i / p_i hex for every entry (large output)",
    )
    args = ap.parse_args()

    target = Path(args.path)

    if target.is_file():
        # Single file mode — infer key_type from path if possible
        path_lower = str(target).lower()
        if "secondary" in path_lower:
            key_type = "secondary"
        elif "primary-advertisements" in path_lower or "primary_advertisements" in path_lower:
            key_type = "primary_advertisements"
        else:
            key_type = "primary"

        parser  = KeysFileParser(str(target), args.uuid, key_type)
        entries = parser.parse()

        print(f"\n{'='*60}")
        print(f"File:        {target.name}")
        print(f"Beacon UUID: {args.uuid or '(not specified)'}")
        print(f"Key type:    {_display_key_type(key_type)}")
        print(f"Key range:   {parser.start_id} → {parser.end_id}")
        print(f"Entries:     {parser.num_entries:,}")
        print(f"Coverage:    ~{parser.time_coverage_hours:.1f} hrs "
              f"({parser.time_coverage_hours/24:.1f} days)")

        print(f"\n--- Sample Report IDs ---")
        for e in entries[:3]:
            print(f"  Key {e.key_id}: {e.report_id}")
        if len(entries) > 3:
            print(f"  ... ({len(entries) - 3:,} more)")

        if args.show_keys:
            print(f"\n--- All Entries ---")
            for e in entries:
                print(e)
                print()

        if args.csv:
            _write_csv(args.csv, parser.to_csv_rows())
            print(f"\nCSV written: {args.csv}")

    elif target.is_dir():
        dir_parser = KeysDirectoryParser(str(target))
        dir_parser.parse_all()

        print(f"\n{'='*60}")
        print(f"Keys folder: {target}")
        for s in dir_parser.file_summary:
            status = f"ERROR: {s['error']}" if s["error"] else f"{s['num_entries']:,} entries"
            print(
                f"  {s['uuid']} / {_display_key_type(s['key_type'])} / "
                f"{s['filename']}  →  {status}"
            )

        total = sum(s["num_entries"] for s in dir_parser.file_summary if not s["error"])
        print(f"\nTotal key pairs: {total:,}")

        if args.csv:
            _write_csv(args.csv, dir_parser.to_csv_rows())
            print(f"CSV written: {args.csv}")

    else:
        print(f"Error: {target} is not a file or directory")
        raise SystemExit(1)


def _write_csv(path: str, rows: List[Dict]) -> None:
    if not rows:
        print("No rows to write.")
        return
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


if __name__ == "__main__":
    _cli_main()
