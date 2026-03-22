
"""
csv_compare_gui.py
==================
On-demand "Compare from CSV" feature for Lost Apples.

Allows a forensic examiner to run the full Observations.db comparison
without first processing a full extraction.  The user provides:
  1. A Lost Apples OwnedBeacons CSV export  (produced by Export Results)
  2. A Lost Apples Observations.db CSV export (produced by Query Observations)

Both the separated key schedule (PWj, 24-hour rotation) and the nearby key
schedule (Pi, 15-minute rotation) are searched in a single pass.  Results
are shown in a color-coded table with a Match_Type column:

  Separated_Key       — PWj byte match against 28-byte Advertised_Data
  Nearby_Key          — Pi MAC match against MAC_Address column
  Latched_Primary_Key — Pi match where Advertised_Data is 28 bytes,
                        meaning the tag transitioned from nearby to separated
                        state while still advertising the primary key Pi
                        (per Apple spec sections 4.6.3.4.6 and 6.3.3.3).

Public entry point
------------------
    show_csv_compare_dialog(app)

    app must have:
      • app.root        — tkinter root or Toplevel
      • app._log(msg, tag)  — GUI logging method
"""

import csv as _csv
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional, Tuple


# ---------------------------------------------------------------------------
# CsvBeaconRecord
# Mirrors OwnedBeaconRecord so the existing engine functions accept it.
# ---------------------------------------------------------------------------

class CsvBeaconRecord:
    """
    A minimal beacon record reconstructed from a Lost Apples OwnedBeacons CSV.

    Attribute names are intentionally identical to OwnedBeaconRecord so this
    object can be passed to any existing key_schedule_gui / nearby_key_schedule_gui
    helper without modification.
    """

    def __init__(self):
        self.identifier: Optional[str]  = None
        self.custom_name: Optional[str] = None
        self.emoji: Optional[str]       = None
        self.model: Optional[str]       = None
        self.pairing_date: Optional[datetime] = None

        # Hex-string key fields — same names as OwnedBeaconRecord
        self.public_key_hex: Optional[str]                      = None
        self.private_key_hex: Optional[str]                     = None
        self.private_scalar_hex: Optional[str]                  = None
        self.shared_secret_hex: Optional[str]                   = None   # SKN0 (nearby)
        self.secondary_shared_secret_hex: Optional[str]         = None   # SKS0 (separated)
        self.secure_locations_shared_secret_hex: Optional[str]  = None


# ---------------------------------------------------------------------------
# CombinedMatch — unified result object for both engines
# ---------------------------------------------------------------------------

class CombinedMatch:
    """
    One confirmed match from either the separated or nearby key search.

    Attributes
    ----------
    match_type          : 'Separated_Key', 'Nearby_Key', or 'Latched_Primary_Key'
    key_index           : day j (separated) or step i (nearby / latched)
    estimated_date_str  : formatted estimate — always labelled as approximate
    derived_ble_str     : colon-separated uppercase BLE MAC derived from key
    key_hex             : full 28-byte PWj or Pi x-coordinate as hex
    observed_mac        : MAC_Address string from the Observations.db row
    observed_time       : Seen_Time string from the Observations.db row
    adv_data_hex        : Advertised_Data from the row (may be empty string)

    Latch-specific (populated only when match_type == 'Latched_Primary_Key')
    -------------------------------------------------------------------------
    separation_window_start : str  — estimated start of the 15-min window
    separation_window_end   : str  — estimated end   of the 15-min window
    expected_pwj_day        : int  — j = i // 96 + 1  (when tag rolls to PWj)
    """

    def __init__(self, match_type: str, key_index: int,
                 estimated_date_str: str, derived_ble_str: str,
                 key_hex: str, observed_mac: str, observed_time: str,
                 adv_data_hex: str = ''):
        self.match_type         = match_type
        self.key_index          = key_index
        self.estimated_date_str = estimated_date_str
        self.derived_ble_str    = derived_ble_str
        self.key_hex            = key_hex
        self.observed_mac       = observed_mac
        self.observed_time      = observed_time
        self.adv_data_hex       = adv_data_hex

        # Latch-specific fields — blank unless reclassified
        self.separation_window_start: str = ''
        self.separation_window_end: str   = ''
        self.expected_pwj_day: int        = 0

        # Multi-beacon tracking — which beacon produced this match
        self.beacon_id: str    = ''
        self.beacon_name: str  = ''
        self.source_phone: str = ''   # e.g. 'Phone 1', 'Phone 2', 'Phone 3'

        # Observation frequency — how many times this MAC / adv was seen
        # across the entire Observations.db, plus all associated timestamps.
        self.observation_count: int        = 0
        self.all_observation_times: list   = []   # List[str]


# ---------------------------------------------------------------------------
# CSV parsing — OwnedBeacons
# ---------------------------------------------------------------------------

_COLUMN_MAP = {
    'Identifier':                           'identifier',
    'Custom_Name':                          'custom_name',
    'Emoji':                                'emoji',
    'Model':                                'model',
    'Public_Key_Hex':                       'public_key_hex',
    'Private_Key_Hex':                      'private_key_hex',
    'Private_Scalar_Hex':                   'private_scalar_hex',
    'Shared_Secret_Hex':                    'shared_secret_hex',
    'Secondary_Shared_Secret_Hex':          'secondary_shared_secret_hex',
    'Secure_Locations_Shared_Secret_Hex':   'secure_locations_shared_secret_hex',
    'Pairing_Date':                         '_pairing_date_raw',
}

_DATE_FORMATS = [
    '%Y-%m-%d %H:%M:%S',
    '%Y-%m-%d %H:%M:%S.%f',
    '%Y-%m-%d',
    '%Y-%m-%dT%H:%M:%S',
    '%Y-%m-%dT%H:%M:%S.%f',
]


def _parse_pairing_date(raw: str) -> Optional[datetime]:
    """Try each known format to parse a Pairing_Date string back to datetime."""
    if not raw or not raw.strip():
        return None
    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(raw.strip(), fmt)
        except ValueError:
            continue
    return None


def load_owned_beacons_csv(csv_path: str) -> List[CsvBeaconRecord]:
    """
    Parse a Lost Apples OwnedBeacons CSV export into CsvBeaconRecord objects.

    Raises ValueError for missing required columns or unreadable file.
    Rows with no Public_Key_Hex are silently skipped.
    """
    path = Path(csv_path)
    if not path.exists():
        raise ValueError(f"File not found: {csv_path}")

    with open(csv_path, 'r', encoding='utf-8', errors='replace', newline='') as f:
        lines = [line for line in f if not line.startswith('#')]

    reader = _csv.DictReader(lines)
    if reader.fieldnames is None:
        raise ValueError("CSV file appears to be empty or has no header row.")

    missing = {'Identifier', 'Public_Key_Hex'} - set(reader.fieldnames)
    if missing:
        raise ValueError(
            f"OwnedBeacons CSV is missing required column(s): "
            f"{', '.join(sorted(missing))}.\n\n"
            "Please make sure you are loading a Lost Apples OwnedBeacons export."
        )

    records: List[CsvBeaconRecord] = []
    for row in reader:
        rec = CsvBeaconRecord()
        for csv_col, attr in _COLUMN_MAP.items():
            raw_val = row.get(csv_col, '').strip()
            if not raw_val:
                continue
            if attr == '_pairing_date_raw':
                rec.pairing_date = _parse_pairing_date(raw_val)
            else:
                setattr(rec, attr, raw_val)
        if rec.public_key_hex:
            records.append(rec)

    return records


# ---------------------------------------------------------------------------
# CSV parsing — Observations.db
# Parses once and returns everything both engines need.
# ---------------------------------------------------------------------------

def _parse_observations_csv(csv_path: str):
    """
    Read the Observations CSV and return five structures in one pass:

    adv_targets : List[Tuple[str, str, str]]
        (adv_hex_56chars, mac_str, seen_time) for every row whose
        Advertised_Data is exactly 28 bytes (56 hex chars).
        Used by the separated key engine.

    mac_targets : List[Tuple[str, str]]
        (mac_str, seen_time) for every row that has a MAC_Address.
        Used by the nearby key engine (de-duplicated by MAC).

    mac_to_adv : dict  {normalised_mac_12hex -> adv_data_hex_str}
        Maps each MAC to its Advertised_Data value.
        Used post-match for latch detection.

    mac_to_all_times : dict  {normalised_mac_12hex -> List[str]}
        Every Seen_Time value recorded for each MAC across all rows
        (not de-duplicated).  Used to populate observation_count and
        all_observation_times on nearby / latched matches.

    adv_to_all_times : dict  {adv_hex_56chars -> List[str]}
        Every Seen_Time value recorded for each unique 28-byte
        advertisement.  Used to populate observation_count and
        all_observation_times on separated key matches.

    Raises ValueError if the file cannot be read.
    """
    adv_targets      = []
    mac_targets      = []
    mac_to_adv       = {}
    mac_to_all_times = {}
    adv_to_all_times = {}

    try:
        with open(csv_path, 'r', encoding='utf-8', errors='replace') as f:
            lines = [l for l in f if not l.startswith('#')]
        reader = _csv.DictReader(lines)
        seen_macs: set = set()

        for row in reader:
            adv = row.get('Advertised_Data', '').replace(' ', '').strip()
            mac = row.get('MAC_Address', '').strip()
            ts  = row.get('Seen_Time', '').strip()

            # Separated engine target: 28-byte advertisement only
            if len(adv) == 56:
                adv_targets.append((adv, mac, ts))
                # Collect every timestamp for this advertisement value
                if adv not in adv_to_all_times:
                    adv_to_all_times[adv] = []
                adv_to_all_times[adv].append(ts)

            # Nearby engine target: any row with a MAC
            if mac:
                norm = mac.upper().replace(':', '').replace('-', '').replace(' ', '')
                if norm not in seen_macs:
                    seen_macs.add(norm)
                    mac_targets.append((mac, ts))
                # Keep adv_data for latch detection (first occurrence wins)
                if norm not in mac_to_adv:
                    mac_to_adv[norm] = adv
                # Collect every timestamp for this MAC across all rows
                if norm not in mac_to_all_times:
                    mac_to_all_times[norm] = []
                mac_to_all_times[norm].append(ts)

    except Exception as exc:
        raise ValueError(f"Could not read Observations CSV:\n{exc}")

    return adv_targets, mac_targets, mac_to_adv, mac_to_all_times, adv_to_all_times


# ---------------------------------------------------------------------------
# Beacon label helper
# ---------------------------------------------------------------------------

def _build_beacon_label(rec: CsvBeaconRecord) -> str:
    uid   = str(rec.identifier or 'Unknown')
    short = uid[:8] + '…' if len(uid) > 8 else uid
    warn  = '' if rec.secondary_shared_secret_hex else '  ⚠ no secondary secret'
    if rec.custom_name and rec.emoji:
        return f"{rec.emoji} {rec.custom_name}  [{short}]{warn}"
    elif rec.custom_name:
        return f"{rec.custom_name}  [{short}]{warn}"
    elif rec.model:
        return f"{rec.model}  [{short}]{warn}"
    return f"[{uid}]{warn}"


# ---------------------------------------------------------------------------
# Combined comparison — background worker
# ---------------------------------------------------------------------------

def _run_combined_comparison(app,
                              records_with_phone: List[Tuple[str, CsvBeaconRecord]],
                              obs_csv_path: str) -> None:
    """
    Run both key schedule searches for every beacon in *records_with_phone*
    against the Observations CSV in a single background pass.

    *records_with_phone* is a list of (phone_label, CsvBeaconRecord) tuples,
    where phone_label is a string such as 'Phone 1', 'Phone 2', or 'Phone 3'.

    For each beacon:
      Phase A: Separated key search (PWj)
      Phase B: Nearby key search (Pi) + latch detection

    Progress bar spans 0–100% across all beacons, divided equally.
    On completion, opens the combined results window on the main thread.
    """
    from src.key_schedule_generator import (
        KeyScheduleGenerator,
        NearbyKeyScheduleGenerator,
    )

    # ---- Parse observations CSV -------------------------------------------
    try:
        adv_targets, mac_targets, mac_to_adv, mac_to_all_times, adv_to_all_times = \
            _parse_observations_csv(obs_csv_path)
    except ValueError as exc:
        messagebox.showerror("CSV Error", str(exc), parent=app.root)
        return

    if not adv_targets and not mac_targets:
        messagebox.showwarning(
            "No Observations Found",
            "The selected CSV contained no usable rows.\n"
            "Please check that the file is a Lost Apples Observations.db export.",
            parent=app.root
        )
        return

    unique_adv = len({t[0] for t in adv_targets})
    unique_mac = len(mac_targets)
    try:
        app._log(f"  CSV Compare: {unique_adv} unique 28-byte adv rows, "
                 f"{unique_mac} unique MACs from {Path(obs_csv_path).name}")
    except Exception:
        pass

    # ---- Progress window --------------------------------------------------
    total_beacons = len(records_with_phone)
    prog_win = tk.Toplevel(app.root)
    prog_win.title("Comparing Keys (Separated + Nearby)…")
    prog_win.geometry("420x150")
    prog_win.resizable(False, False)
    prog_win.transient(app.root)

    tk.Label(prog_win,
             text="Searching separated and nearby key chains…",
             font=('Helvetica', 11)).pack(pady=(16, 6))
    pb = ttk.Progressbar(prog_win, length=360, mode='determinate')
    pb.pack(padx=30)
    phase_lbl = tk.Label(prog_win,
                         text=f"Beacon 1 of {total_beacons}: Separated keys…",
                         font=('Helvetica', 9))
    phase_lbl.pack(pady=(4, 0))
    status_lbl = tk.Label(prog_win, text="Starting…", font=('Helvetica', 8),
                          fg='#555555')
    status_lbl.pack()

    results_holder = [None]
    error_holder   = [None]

    # Each beacon occupies an equal share of the 0–100% progress range.
    # Within that share, the first half is separated and the second is nearby.
    beacon_share = 100.0 / total_beacons

    def make_progress_callbacks(beacon_idx: int):
        """Return (progress_sep, progress_near) callbacks for one beacon."""
        base = beacon_idx * beacon_share

        def progress_sep(current, total):
            def _upd():
                try:
                    pb['value'] = int(base + current / total * beacon_share * 0.5)
                    status_lbl.config(text=f"Beacon {beacon_idx + 1}/{total_beacons}: "
                                          f"step {current} of {total}")
                except Exception:
                    pass
            try:
                app.root.after(0, _upd)
            except Exception:
                pass

        def progress_near(current, total):
            def _upd():
                try:
                    pb['value'] = int(base + beacon_share * 0.5
                                      + current / total * beacon_share * 0.5)
                    status_lbl.config(text=f"Beacon {beacon_idx + 1}/{total_beacons}: "
                                          f"step {current} of {total}")
                except Exception:
                    pass
            try:
                app.root.after(0, _upd)
            except Exception:
                pass

        return progress_sep, progress_near

    def set_phase(text: str):
        def _upd():
            try:
                phase_lbl.config(text=text)
            except Exception:
                pass
        try:
            app.root.after(0, _upd)
        except Exception:
            pass

    def worker():
        combined: List[CombinedMatch] = []

        try:
            for beacon_idx, (phone_label, record) in enumerate(records_with_phone):
                pub_key = bytes.fromhex(record.public_key_hex)
                pairing = record.pairing_date

                # The 28-byte private scalar enables the fast OpenSSL derivation
                # path (~1000× faster).  Falls back silently if absent.
                d0 = bytes.fromhex(record.private_scalar_hex) \
                     if record.private_scalar_hex else None

                bid   = str(record.identifier or 'Unknown')
                bname = record.custom_name or bid[:8]

                # Compute key-range bounds from pairing date
                _today   = datetime.now()
                _pairing = pairing
                if _pairing and _pairing < _today:
                    SEP_MAX  = max(1, (_today - _pairing).days + 7)
                    NEAR_MAX = max(1, int((_today - _pairing).total_seconds() / 900) + 96)
                else:
                    SEP_MAX  = 3000
                    NEAR_MAX = 105120

                try:
                    app._log(f"  [{phone_label} / {bname}] Key range: {SEP_MAX} day(s) "
                             f"separated / {NEAR_MAX} step(s) nearby")
                except Exception:
                    pass

                progress_sep, progress_near = make_progress_callbacks(beacon_idx)

                # ------------------------------------------------------------------
                # Phase A: Separated key search (PWj)
                # ------------------------------------------------------------------
                sep_secret = record.secondary_shared_secret_hex or record.shared_secret_hex

                if sep_secret and adv_targets:
                    set_phase(f"Beacon {beacon_idx + 1}/{total_beacons}: "
                              f"Separated keys (PWj)…")
                    sks0    = bytes.fromhex(sep_secret)
                    sep_gen = KeyScheduleGenerator(pub_key, sks0, pairing, d0=d0)
                    sep_matches = sep_gen.search_observations(
                        adv_targets,
                        max_days=SEP_MAX,
                        progress_callback=progress_sep,
                    )
                    for m in sep_matches:
                        adv_hex  = m.pw_j_bytes.hex()
                        adv_times = adv_to_all_times.get(adv_hex, [m.observed_time])
                        cm = CombinedMatch(
                            match_type         = 'Separated_Key',
                            key_index          = m.day_index,
                            estimated_date_str = m.estimated_date_str,
                            derived_ble_str    = m.ble_address_str,
                            key_hex            = adv_hex,
                            observed_mac       = m.observed_mac,
                            observed_time      = m.observed_time,
                            adv_data_hex       = adv_hex,
                        )
                        cm.observation_count      = len(adv_times)
                        cm.all_observation_times  = adv_times
                        cm.beacon_id   = bid
                        cm.beacon_name = bname
                        cm.source_phone = phone_label
                        combined.append(cm)
                else:
                    # Advance progress to halfway point for this beacon
                    _base = beacon_idx * beacon_share
                    def _skip_sep(b=_base):
                        try:
                            pb['value'] = int(b + beacon_share * 0.5)
                        except Exception:
                            pass
                    try:
                        app.root.after(0, _skip_sep)
                    except Exception:
                        pass

                # ------------------------------------------------------------------
                # Phase B: Nearby key search (Pi)
                # ------------------------------------------------------------------
                if record.shared_secret_hex and mac_targets:
                    set_phase(f"Beacon {beacon_idx + 1}/{total_beacons}: "
                              f"Nearby keys (Pi)…")
                    skn0     = bytes.fromhex(record.shared_secret_hex)
                    near_gen = NearbyKeyScheduleGenerator(pub_key, skn0, pairing, d0=d0)
                    near_matches = near_gen.search_observations(
                        mac_targets,
                        max_steps=NEAR_MAX,
                        progress_callback=progress_near,
                    )

                    for m in near_matches:
                        norm_mac = (m.observed_mac.upper()
                                    .replace(':', '').replace('-', '').replace(' ', ''))
                        adv_hex  = mac_to_adv.get(norm_mac, '')
                        is_latch = len(adv_hex) == 56

                        # Collect all observation timestamps for this MAC
                        all_times = mac_to_all_times.get(norm_mac, [m.observed_time])

                        if is_latch:
                            i         = m.step_index
                            win_start = pairing + timedelta(minutes=(i - 1) * 15)
                            win_end   = pairing + timedelta(minutes=i * 15)
                            pwj_day   = i // 96 + 1

                            cm = CombinedMatch(
                                match_type         = 'Latched_Primary_Key',
                                key_index          = i,
                                estimated_date_str = m.estimated_datetime_str,
                                derived_ble_str    = m.ble_address_str,
                                key_hex            = m.p_i_bytes.hex(),
                                observed_mac       = m.observed_mac,
                                observed_time      = m.observed_time,
                                adv_data_hex       = adv_hex,
                            )
                            cm.separation_window_start = win_start.strftime('%Y-%m-%d %H:%M')
                            cm.separation_window_end   = win_end.strftime('%Y-%m-%d %H:%M')
                            cm.expected_pwj_day        = pwj_day
                        else:
                            cm = CombinedMatch(
                                match_type         = 'Nearby_Key',
                                key_index          = m.step_index,
                                estimated_date_str = m.estimated_datetime_str,
                                derived_ble_str    = m.ble_address_str,
                                key_hex            = m.p_i_bytes.hex(),
                                observed_mac       = m.observed_mac,
                                observed_time      = m.observed_time,
                                adv_data_hex       = adv_hex,
                            )
                        cm.observation_count      = len(all_times)
                        cm.all_observation_times  = all_times
                        cm.beacon_id   = bid
                        cm.beacon_name = bname
                        cm.source_phone = phone_label
                        combined.append(cm)

            results_holder[0] = combined

        except Exception as exc:
            import traceback
            error_holder[0] = f"{exc}\n{traceback.format_exc()}"

    t = threading.Thread(target=worker, daemon=True)
    t.start()

    def check():
        if t.is_alive():
            app.root.after(100, check)
        else:
            try:
                prog_win.destroy()
            except Exception:
                pass

            if error_holder[0] is not None:
                messagebox.showerror("Error",
                                     f"Comparison failed:\n{error_holder[0]}",
                                     parent=app.root)
                try:
                    app._log(f"  ✗ Combined comparison error: {error_holder[0]}", "error")
                except Exception:
                    pass
            elif results_holder[0] is not None:
                _show_combined_results(app, records_with_phone, results_holder[0], obs_csv_path)

    app.root.after(100, check)


# ---------------------------------------------------------------------------
# Dark mode detection
# ---------------------------------------------------------------------------

def _is_dark_mode(root) -> bool:
    """
    Return True if the system is currently using dark mode.

    Checks macOS first, then Windows, then falls back to probing the
    tkinter root window background colour luminance.
    """
    import platform
    try:
        if platform.system() == 'Darwin':
            import subprocess
            result = subprocess.run(
                ['defaults', 'read', '-g', 'AppleInterfaceStyle'],
                capture_output=True, text=True, timeout=1,
            )
            return result.stdout.strip().lower() == 'dark'
    except Exception:
        pass
    try:
        if platform.system() == 'Windows':
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r'Software\Microsoft\Windows\CurrentVersion\Themes\Personalize',
            )
            val, _ = winreg.QueryValueEx(key, 'AppsUseLightTheme')
            winreg.CloseKey(key)
            return val == 0
    except Exception:
        pass
    # Fallback: measure the root window background luminance.
    # winfo_rgb returns values in the 0–65535 range; divide by 256 to get 0–255.
    try:
        r, g, b = [c // 256 for c in root.winfo_rgb(root.cget('background'))]
        return (0.299 * r + 0.587 * g + 0.114 * b) < 128
    except Exception:
        return False


# Row colour palettes — each entry is (background, foreground).
# Two palettes so both light mode and dark mode get good contrast.

_TAG_COLOURS_LIGHT = {
    'Separated_Key':       ('#d6eaf8', '#1a3a5c'),   # soft blue bg,  dark blue text
    'Nearby_Key':          ('#d5f5e3', '#145a32'),   # soft green bg, dark green text
    'Latched_Primary_Key': ('#fef9e7', '#7d6608'),   # soft amber bg, dark amber text
}

_TAG_COLOURS_DARK = {
    'Separated_Key':       ('#1a3a5c', '#a8d4f5'),   # deep blue bg,  light blue text
    'Nearby_Key':          ('#1a4a2e', '#80e0a0'),   # deep green bg, light green text
    'Latched_Primary_Key': ('#4a3800', '#f5d060'),   # deep amber bg, light gold text
}

# Short label shown in the Match_Type column
_TYPE_LABELS = {
    'Separated_Key':       'Separated (PWj)',
    'Nearby_Key':          'Nearby (Pi)',
    'Latched_Primary_Key': '⚡ Latched Pi→Sep',
}


# ---------------------------------------------------------------------------
# Combined results window
# ---------------------------------------------------------------------------

def _show_combined_results(app,
                            records_with_phone: List[Tuple[str, CsvBeaconRecord]],
                            matches: List[CombinedMatch],
                            obs_csv_path: str,
                            mode: str = "combined") -> None:
    """
    Display all combined matches in a single colour-coded results window.

    *records_with_phone* is a list of (phone_label, CsvBeaconRecord) tuples.
    A Source_Phone column identifies which phone CSV each row came from.
    Row colours adapt to the system appearance.
    """
    # Build per-beacon summary info for header/title
    records        = [r for _, r in records_with_phone]
    total_beacons  = len(records)
    if total_beacons == 1:
        record      = records[0]
        beacon_id   = str(record.identifier or 'Unknown')
        beacon_name = record.custom_name or ''
        emoji       = record.emoji or ''
        if beacon_name and emoji:
            title_str = f"{emoji} {beacon_name}  [{beacon_id[:8]}…]"
        elif beacon_name:
            title_str = f"{beacon_name}  [{beacon_id[:8]}…]"
        else:
            title_str = f"[{beacon_id}]"
    else:
        matched_beacons = len({m.beacon_id for m in matches if m.beacon_id})
        title_str = f"{matched_beacons} Beacon{'s' if matched_beacons != 1 else ''}"

    # Count by type for the log and header
    sep_count   = sum(1 for m in matches if m.match_type == 'Separated_Key')
    near_count  = sum(1 for m in matches if m.match_type == 'Nearby_Key')
    latch_count = sum(1 for m in matches if m.match_type == 'Latched_Primary_Key')

    if matches:
        try:
            app._log(
                f"  ✓ Combined match results for {title_str}: "
                f"{sep_count} separated, {near_count} nearby, "
                f"{latch_count} latched",
                "success"
            )
        except Exception:
            pass
    else:
        try:
            app._log(
                f"  ⚠ No matches found for {title_str} in "
                f"{Path(obs_csv_path).name}",
                "warning"
            )
        except Exception:
            pass

    # beacon_id is used by the export filename; use first record or "multi"
    beacon_id = (str(records[0].identifier or 'Unknown')
                 if total_beacons == 1 else 'multi_beacon')

    win = tk.Toplevel(app.root)
    _window_label = "Wild Mode Matches" if mode == "wild_mode" else "Combined Observation Matches"
    win.title(f"{_window_label} — {title_str}")
    win.geometry("1200x560")
    win.resizable(True, True)
    win.transient(app.root)

    # Detect dark/light mode once per window so all colours are consistent.
    TAG_COLOURS = _TAG_COLOURS_DARK if _is_dark_mode(app.root) else _TAG_COLOURS_LIGHT

    # ---- Header bar --------------------------------------------------------
    hdr = tk.Frame(win, bg='#1e3a5f', pady=8)
    hdr.pack(fill='x')
    tk.Label(hdr,
             text=f"🔍  {_window_label}  |  {title_str}",
             bg='#1e3a5f', fg='white',
             font=('Helvetica', 12, 'bold')).pack(side='left', padx=12)

    # Colour-coded summary counts on the right
    summary_frame = tk.Frame(hdr, bg='#1e3a5f')
    summary_frame.pack(side='right', padx=12)
    if sep_count:
        _bg, _fg = TAG_COLOURS['Separated_Key']
        tk.Label(summary_frame, text=f"  {sep_count} Separated",
                 bg=_bg, fg=_fg, font=('Helvetica', 9, 'bold'),
                 padx=6, pady=2, relief='flat').pack(side='left', padx=2)
    if near_count:
        _bg, _fg = TAG_COLOURS['Nearby_Key']
        tk.Label(summary_frame, text=f"  {near_count} Nearby",
                 bg=_bg, fg=_fg, font=('Helvetica', 9, 'bold'),
                 padx=6, pady=2, relief='flat').pack(side='left', padx=2)
    if latch_count:
        _bg, _fg = TAG_COLOURS['Latched_Primary_Key']
        tk.Label(summary_frame, text=f"  {latch_count} Latched",
                 bg=_bg, fg=_fg, font=('Helvetica', 9, 'bold'),
                 padx=6, pady=2, relief='flat').pack(side='left', padx=2)
    if not matches:
        tk.Label(summary_frame, text="No matches",
                 bg='#1e3a5f', fg='#aac4e0',
                 font=('Helvetica', 10)).pack(side='left')

    # ---- No-match message -------------------------------------------------
    if not matches:
        msg = (
            "No keys from either the separated (PWj) or nearby (Pi) schedule\n"
            "matched any entry in the selected Observations.db CSV.\n\n"
            "Possible reasons:\n"
            "  • The beacon was not within BLE range of the scanning device\n"
            "    during the time window covered by the Observations.db.\n"
            "  • The Observations.db is from a different device.\n"
            "  • iOS has rotated one or both shared secrets after pairing,\n"
            "    shifting the key schedule away from the pairing date anchor.\n"
            "  • The CSV was produced with a different version of the OwnedBeacons\n"
            "    export — check that Public_Key_Hex and key fields are populated."
        )
        tk.Label(win, text=msg, font=('Helvetica', 10),
                 justify='left', padx=20, pady=20).pack(anchor='w')
        return

    # ---- Treeview table ---------------------------------------------------
    # 'source_phone' and 'beacon_name' are always included.
    cols = (
        'source_phone', 'beacon_name', 'match_type', 'key_index',
        'derived_ble', 'observed_mac', 'observed_time', 'obs_count',
        'key_hex',
        'sep_win_start', 'sep_win_end', 'pwj_day',
    )
    col_cfg = {
        'source_phone':  ('Source Phone',             90,  'w'),
        'beacon_name':   ('Beacon',                  160,  'w'),
        'match_type':    ('Match Type',              155,  'w'),
        'key_index':     ('Key Index',                70,  'center'),
        'derived_ble':   ('Derived BLE',             150,  'center'),
        'observed_mac':  ('Observed MAC',            150,  'center'),
        'observed_time': ('Seen Time',               175,  'center'),
        'obs_count':     ('Obs. Count',               75,  'center'),
        'key_hex':       ('Key Hex (28 bytes)',       340,  'w'),
        'sep_win_start': ('Sep. Window Start',        145,  'center'),
        'sep_win_end':   ('Sep. Window End',          145,  'center'),
        'pwj_day':       ('Exp. PWj Day',              80,  'center'),
    }

    tree_frame = tk.Frame(win)
    tree_frame.pack(fill='both', expand=True, padx=8, pady=6)

    vsb = ttk.Scrollbar(tree_frame, orient='vertical')
    hsb = ttk.Scrollbar(tree_frame, orient='horizontal')
    tree = ttk.Treeview(tree_frame, columns=cols, show='headings',
                         yscrollcommand=vsb.set, xscrollcommand=hsb.set,
                         height=18)
    vsb.config(command=tree.yview)
    hsb.config(command=tree.xview)
    vsb.pack(side='right', fill='y')
    hsb.pack(side='bottom', fill='x')
    tree.pack(fill='both', expand=True)

    style = ttk.Style()
    style.configure('Treeview',         font=('Courier', 9), rowheight=20)
    style.configure('Treeview.Heading', font=('Helvetica', 9, 'bold'))

    for col, (heading, width, anchor) in col_cfg.items():
        tree.heading(col, text=heading)
        tree.column(col, width=width, minwidth=40, anchor=anchor)

    # Configure colour tags — background and foreground adapt to light/dark mode
    for tag, (_bg, _fg) in TAG_COLOURS.items():
        tree.tag_configure(tag, background=_bg, foreground=_fg)

    # Sort by observed_time so the table is in chronological order
    def _sort_key(m: CombinedMatch):
        try:
            return datetime.strptime(m.observed_time[:19], '%Y-%m-%d %H:%M:%S')
        except Exception:
            return datetime.min

    # item_id → CombinedMatch, so the double-click handler can reach the
    # full all_observation_times list for the selected row.
    item_to_match: dict = {}

    for m in sorted(matches, key=_sort_key):
        tag = m.match_type
        iid = tree.insert('', 'end', values=(
            m.source_phone,
            m.beacon_name,
            _TYPE_LABELS.get(m.match_type, m.match_type),
            m.key_index,
            m.derived_ble_str,
            m.observed_mac,
            m.observed_time,
            m.observation_count if m.observation_count > 0 else '',
            m.key_hex,
            m.separation_window_start,
            m.separation_window_end,
            m.expected_pwj_day or '',
        ), tags=(tag,))
        item_to_match[iid] = m

    # ---- Double-click handler — show all observation timestamps -----------
    def _on_row_double_click(event):
        """Open a small popup listing every Seen_Time for the selected row."""
        sel = tree.selection()
        if not sel:
            return
        iid  = sel[0]
        m    = item_to_match.get(iid)
        if m is None:
            return

        popup = tk.Toplevel(win)
        popup.title(f"All Observations — {m.observed_mac}")
        popup.geometry("400x320")
        popup.resizable(True, True)
        popup.transient(win)

        # Header
        hdr2 = tk.Frame(popup, bg='#1e3a5f', pady=6)
        hdr2.pack(fill='x')
        tk.Label(hdr2,
                 text=f"All Observations for {m.observed_mac}",
                 bg='#1e3a5f', fg='white',
                 font=('Helvetica', 11, 'bold')).pack(side='left', padx=10)
        count_str = (f"{m.observation_count} observation"
                     f"{'s' if m.observation_count != 1 else ''}")
        tk.Label(hdr2, text=count_str,
                 bg='#1e3a5f', fg='#aac4e0',
                 font=('Helvetica', 9)).pack(side='right', padx=10)

        # Scrollable listbox of timestamps
        lf = tk.Frame(popup)
        lf.pack(fill='both', expand=True, padx=8, pady=8)
        lb_vsb = ttk.Scrollbar(lf, orient='vertical')
        lb = tk.Listbox(lf, font=('Courier', 10),
                        yscrollcommand=lb_vsb.set, selectmode='browse')
        lb_vsb.config(command=lb.yview)
        lb_vsb.pack(side='right', fill='y')
        lb.pack(side='left', fill='both', expand=True)

        times = m.all_observation_times if m.all_observation_times else [m.observed_time]
        for idx, ts in enumerate(times, 1):
            lb.insert('end', f"  {idx:>3}.  {ts}")

        tk.Button(popup, text="Close", command=popup.destroy,
                  font=('Helvetica', 10), padx=10, pady=3).pack(pady=(0, 8))

    tree.bind('<Double-1>', _on_row_double_click)

    # ---- Legend -----------------------------------------------------------
    legend_frame = tk.Frame(win, pady=4)
    legend_frame.pack(fill='x', padx=8)

    tk.Label(legend_frame, text="Legend: ",
             font=('Helvetica', 8, 'bold')).pack(side='left')
    for mtype, (_bg, _fg) in TAG_COLOURS.items():
        tk.Label(legend_frame,
                 text=f"  {_TYPE_LABELS[mtype]}  ",
                 bg=_bg, fg=_fg, font=('Helvetica', 8),
                 relief='groove', padx=4).pack(side='left', padx=3)

    # ---- Bottom bar -------------------------------------------------------
    bar = tk.Frame(win, pady=6)
    bar.pack(fill='x', padx=8)

    tk.Label(
        bar,
        text=(
            "⚡ Latched rows: beacon transitioned to separated state while still "
            "advertising primary key Pi (Apple spec §4.6.3.4.6).  "
            "Sep. Window Start/End shows the estimated 15-min window of that transition.  "
            "Double-click any row to see all observation timestamps for that beacon."
        ),
        font=('Helvetica', 8), fg='#555555',
        wraplength=1000, justify='left'
    ).pack(side='left')

    def export_csv():
        beacon_short = beacon_id[:8]
        path = filedialog.asksaveasfilename(
            parent=win,
            defaultextension='.csv',
            filetypes=[('CSV files', '*.csv'), ('All files', '*.*')],
            initialfile=f'combined_matches_{beacon_short}.csv',
            title='Save Combined Match Results CSV',
        )
        if not path:
            return
        _export_combined_csv(matches, beacon_id, path)
        messagebox.showinfo("Exported",
                            f"Combined match results saved to:\n{path}",
                            parent=win)
        try:
            app._log(f"  ✓ Combined match results exported: {path}", "success")
        except Exception:
            pass

    tk.Button(bar, text="📄  Export CSV", command=export_csv,
              font=('Helvetica', 10, 'bold'),
              padx=10, pady=3, cursor='hand2').pack(side='right')


# ---------------------------------------------------------------------------
# CSV export for combined results
# ---------------------------------------------------------------------------

def _export_combined_csv(matches: List[CombinedMatch],
                          beacon_id: str, output_path: str) -> None:
    """
    Write the combined match list to CSV.

    Columns
    -------
    Source_Phone          — which phone CSV the match came from
    Beacon_ID             — UUID of the OwnedBeacon
    Beacon_Name           — Friendly name / custom name of the beacon
    Match_Type            — Separated_Key | Nearby_Key | Latched_Primary_Key
    Key_Index             — day j (separated) or step i (nearby/latched)
    Est_Date_Active       — estimated key activation date/time [APPROXIMATE]
    Derived_BLE_Address   — 6-byte MAC derived from the key
    Key_Hex               — 28-byte PWj or Pi x-coordinate as hex
    Observed_MAC          — MAC_Address from Observations.db
    Observed_Time         — Seen_Time from Observations.db
    Observation_Count     — total rows in Observations.db matching this MAC/adv
    All_Observation_Times — semicolon-separated list of every Seen_Time
    Advertised_Data_Hex   — full Advertised_Data from Observations.db row
    Sep_Window_Start      — (Latched only) estimated separation window start
    Sep_Window_End        — (Latched only) estimated separation window end
    Expected_PWj_Day      — (Latched only) j = i // 96 + 1
    """
    import csv
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([
            'Source_Phone', 'Beacon_ID', 'Beacon_Name', 'Match_Type', 'Key_Index',
            'Est_Date_Active', 'Derived_BLE_Address', 'Key_Hex',
            'Observed_MAC', 'Observed_Time', 'Observation_Count',
            'All_Observation_Times', 'Advertised_Data_Hex',
            'Sep_Window_Start', 'Sep_Window_End', 'Expected_PWj_Day',
        ])
        for m in matches:
            # Collapse the list of timestamps into a single semicolon-separated
            # string so each match still occupies exactly one CSV row.
            all_times_str = '; '.join(m.all_observation_times) if m.all_observation_times else ''
            writer.writerow([
                m.source_phone,
                m.beacon_id or beacon_id,
                m.beacon_name,
                m.match_type,
                m.key_index,
                m.estimated_date_str,
                m.derived_ble_str,
                m.key_hex,
                m.observed_mac,
                m.observed_time,
                m.observation_count if m.observation_count > 0 else '',
                all_times_str,
                m.adv_data_hex,
                m.separation_window_start,
                m.separation_window_end,
                m.expected_pwj_day if m.expected_pwj_day else '',
            ])


# ---------------------------------------------------------------------------
# Public entry point — unified CSV comparison dialog
# ---------------------------------------------------------------------------

def show_csv_compare_dialog(app) -> None:
    """
    Launch the on-demand CSV comparison workflow (multi-phone edition).

    Opens a single dialog where the user can:
      1. Browse for up to three Lost Apples OwnedBeacons CSV exports
         (one per phone; Phone 1 is required, Phones 2 and 3 are optional).
      2. Browse for a Lost Apples Observations.db CSV.
      3. Select which beacon(s) to compare — grouped by phone.
      4. Press "Run Comparison" to start the analysis.

    Parameters
    ----------
    app : SearchpartydGUI (or any object with .root and ._log)
    """

    NUM_PHONES = 3

    # ---- Top-level window --------------------------------------------------
    dlg = tk.Toplevel(app.root)
    dlg.title("Compare from CSV — Lost Apples")
    dlg.geometry("680x780")
    dlg.resizable(False, False)
    dlg.transient(app.root)
    dlg.grab_set()

    dlg.update_idletasks()
    px = app.root.winfo_rootx() + (app.root.winfo_width()  - 680) // 2
    py = app.root.winfo_rooty() + (app.root.winfo_height() - 780) // 2
    dlg.geometry(f'+{px}+{py}')

    # ---- Header ------------------------------------------------------------
    hdr = tk.Frame(dlg, bg='#1e3a5f', pady=10)
    hdr.pack(fill='x')
    tk.Label(hdr,
             text="Compare OwnedBeacons vs Observations  (CSV mode)",
             bg='#1e3a5f', fg='white',
             font=('Helvetica', 13, 'bold')).pack()
    tk.Label(hdr,
             text="Up to three phones · both separated (PWj) and nearby (Pi) key schedules",
             bg='#1e3a5f', fg='#aac4e0',
             font=('Helvetica', 9)).pack()

    # ---- Body --------------------------------------------------------------
    body = tk.Frame(dlg, padx=20, pady=10)
    body.pack(fill='both', expand=True)
    body.columnconfigure(1, weight=1)

    # ---- Colour palette (adapts to system light / dark mode) ---------------
    _dark = _is_dark_mode(app.root)
    _entry_bg  = '#2d2d2d' if _dark else '#f5f5f5'
    _entry_fg  = '#e8e8e8' if _dark else '#000000'
    _frame_bg  = '#1e1e1e' if _dark else '#ffffff'
    _ph_fg     = '#888888' if _dark else '#999999'
    _hdr_bg    = '#2a4a70' if _dark else '#dce8f7'
    _hdr_fg    = '#aac4e0' if _dark else '#1a3a5c'

    # ---- Per-phone state ---------------------------------------------------
    # phone_records[i]    : List[CsvBeaconRecord] loaded from phone i
    # phone_path_vars[i]  : StringVar shown in the entry widget (filename only)
    # phone_full_paths[i] : full absolute path, or '' if not yet loaded
    # phone_name_vars[i]  : StringVar for the user-supplied label
    phone_records    = [[], [], []]
    phone_path_vars  = [tk.StringVar() for _ in range(NUM_PHONES)]
    phone_full_paths = ['', '', '']
    phone_name_vars  = [tk.StringVar() for _ in range(NUM_PHONES)]

    obs_path_var     = tk.StringVar()
    sel_count_var    = tk.StringVar(value="0 beacons selected")

    # check_items : List[Tuple[int, int, tk.BooleanVar]]
    #   Each entry is (phone_idx, record_idx, BooleanVar) so we can map
    #   a checkbox back to the right phone and record.
    check_items: list = []

    def _update_count(*_):
        n = sum(v.get() for _, _, v in check_items)
        sel_count_var.set(f"{n} beacon{'s' if n != 1 else ''} selected")

    # ---- Phone row builder -------------------------------------------------
    phone_status_vars = [tk.StringVar(value="") for _ in range(NUM_PHONES)]
    phone_status_lbls = [None] * NUM_PHONES

    phone_labels_text = ["Phone 1  (required)", "Phone 2  (optional)", "Phone 3  (optional)"]

    current_row = [0]   # mutable counter for grid rows

    def _add_phone_row(phone_idx: int):
        label_text = phone_labels_text[phone_idx]
        row = current_row[0]

        tk.Label(body, text=label_text, font=('Helvetica', 10, 'bold'),
                 anchor='w').grid(row=row, column=0, sticky='w', pady=(6, 2))

        pf = tk.Frame(body)
        pf.grid(row=row, column=1, sticky='ew', pady=(6, 2), padx=(8, 0))
        pf.columnconfigure(0, weight=1)

        pe = tk.Entry(pf, textvariable=phone_path_vars[phone_idx],
                      state='readonly', font=('Helvetica', 9),
                      readonlybackground=_entry_bg, fg=_entry_fg,
                      relief='sunken')
        pe.grid(row=0, column=0, sticky='ew')

        def _make_browse(idx):
            def _browse():
                path = filedialog.askopenfilename(
                    parent=dlg,
                    title=f"Select Phone {idx + 1} OwnedBeacons CSV export",
                    filetypes=[('CSV files', '*.csv'), ('All files', '*.*')],
                )
                if path:
                    _load_phone_beacons(idx, path)
            return _browse

        tk.Button(pf, text="Browse…", command=_make_browse(phone_idx),
                  font=('Helvetica', 9), padx=8).grid(row=0, column=1, padx=(6, 0))

        # ---- Name entry row ------------------------------------------------
        nf = tk.Frame(body)
        nf.grid(row=row + 1, column=1, sticky='ew', pady=(2, 0), padx=(8, 0))
        nf.columnconfigure(1, weight=1)
        tk.Label(nf, text="Label:", font=('Helvetica', 8),
                 fg='#888888', anchor='w').grid(row=0, column=0, sticky='w', padx=(0, 4))
        tk.Entry(nf, textvariable=phone_name_vars[phone_idx],
                 font=('Helvetica', 9), width=28,
                 bg=_entry_bg, fg=_entry_fg,
                 relief='sunken').grid(row=0, column=1, sticky='ew')

        sv = phone_status_vars[phone_idx]
        sl = tk.Label(body, textvariable=sv,
                      font=('Helvetica', 8), fg='#777777', anchor='w')
        sl.grid(row=row + 2, column=1, sticky='w', padx=(8, 0), pady=(0, 2))
        phone_status_lbls[phone_idx] = sl

        current_row[0] += 3

    for i in range(NUM_PHONES):
        _add_phone_row(i)

    # ---- Divider -----------------------------------------------------------
    ttk.Separator(body, orient='horizontal').grid(
        row=current_row[0], column=0, columnspan=2,
        sticky='ew', pady=(6, 4))
    current_row[0] += 1

    # ---- Observations CSV row ---------------------------------------------
    obs_row = current_row[0]
    tk.Label(body, text="Observations CSV:", font=('Helvetica', 10, 'bold'),
             anchor='w').grid(row=obs_row, column=0, sticky='w', pady=(4, 2))

    obs_frame = tk.Frame(body)
    obs_frame.grid(row=obs_row, column=1, sticky='ew', pady=(4, 2), padx=(8, 0))
    obs_frame.columnconfigure(0, weight=1)

    obs_entry = tk.Entry(obs_frame, textvariable=obs_path_var,
                         state='readonly', font=('Helvetica', 9),
                         readonlybackground=_entry_bg, fg=_entry_fg,
                         relief='sunken')
    obs_entry.grid(row=0, column=0, sticky='ew')

    def _browse_obs():
        path = filedialog.askopenfilename(
            parent=dlg,
            title="Select Lost Apples Observations.db CSV export",
            filetypes=[('CSV files', '*.csv'), ('All files', '*.*')],
        )
        if not path:
            return
        obs_path_var.set(Path(path).name)
        _browse_obs._full_path = path

    _browse_obs._full_path = ''

    tk.Button(obs_frame, text="Browse…", command=_browse_obs,
              font=('Helvetica', 9), padx=8).grid(row=0, column=1, padx=(6, 0))

    current_row[0] += 1

    # ---- Beacon selector ---------------------------------------------------
    sel_row = current_row[0]
    tk.Label(body, text="Select beacon(s):", font=('Helvetica', 10, 'bold'),
             anchor='nw').grid(row=sel_row, column=0, sticky='nw', pady=(8, 2))

    cb_outer = tk.Frame(body, relief='sunken', bd=1)
    cb_outer.grid(row=sel_row, column=1, sticky='nsew',
                  pady=(8, 2), padx=(8, 0))
    body.rowconfigure(sel_row, weight=1)

    cb_canvas = tk.Canvas(cb_outer, highlightthickness=0, height=160,
                           bg=_frame_bg)
    cb_scroll = ttk.Scrollbar(cb_outer, orient='vertical',
                               command=cb_canvas.yview)
    cb_canvas.configure(yscrollcommand=cb_scroll.set)

    cb_scroll.pack(side='right', fill='y')
    cb_canvas.pack(side='left', fill='both', expand=True)

    cb_inner = tk.Frame(cb_canvas, bg=_frame_bg)
    cb_window = cb_canvas.create_window((0, 0), window=cb_inner, anchor='nw')

    def _on_canvas_configure(event):
        cb_canvas.itemconfig(cb_window, width=event.width)
    cb_canvas.bind('<Configure>', _on_canvas_configure)

    def _on_inner_configure(event):
        cb_canvas.configure(scrollregion=cb_canvas.bbox('all'))
    cb_inner.bind('<Configure>', _on_inner_configure)

    def _on_mousewheel(event):
        try:
            import platform
            if platform.system() == 'Darwin':
                cb_canvas.yview_scroll(-1 * event.delta, 'units')
            else:
                cb_canvas.yview_scroll(-1 * (event.delta // 120), 'units')
        except Exception:
            pass
    cb_canvas.bind('<MouseWheel>', _on_mousewheel)
    cb_inner.bind('<MouseWheel>', _on_mousewheel)

    # Placeholder shown before any beacons are loaded
    placeholder_lbl = tk.Label(cb_inner,
                                text="Load an OwnedBeacons CSV above to populate this list.",
                                font=('Helvetica', 9), fg=_ph_fg,
                                bg=_frame_bg, pady=12)
    placeholder_lbl.pack()

    current_row[0] += 1

    # ---- Select All / Deselect All ----------------------------------------
    sa_row = current_row[0]
    sel_btn_row = tk.Frame(body)
    sel_btn_row.grid(row=sa_row, column=1, sticky='w', padx=(8, 0), pady=(2, 0))

    def select_all():
        for _, _, v in check_items:
            v.set(True)
        _update_count()

    def deselect_all():
        for _, _, v in check_items:
            v.set(False)
        _update_count()

    sel_all_btn = tk.Button(sel_btn_row, text="Select All", command=select_all,
                             font=('Helvetica', 8), padx=6, pady=1,
                             state='disabled')
    sel_all_btn.pack(side='left', padx=(0, 4))

    desel_all_btn = tk.Button(sel_btn_row, text="Deselect All", command=deselect_all,
                               font=('Helvetica', 8), padx=6, pady=1,
                               state='disabled')
    desel_all_btn.pack(side='left')

    sel_count_lbl = tk.Label(sel_btn_row, textvariable=sel_count_var,
                              font=('Helvetica', 8), fg='#555555')
    sel_count_lbl.pack(side='left', padx=(10, 0))

    current_row[0] += 1

    # ---- Info box ----------------------------------------------------------
    info_row = current_row[0]
    info = tk.Text(body, height=5, width=62, wrap='word',
                   relief='flat', font=('Helvetica', 9), padx=6, pady=6)
    info.grid(row=info_row, column=0, columnspan=2, sticky='ew', pady=(8, 0))
    info.insert('1.0',
        "Load OwnedBeacons CSVs for up to three phones, select beacon(s), load an "
        "Observations CSV, then click \"Run Comparison\".\n\n"
        "Both key schedules will be searched for every selected beacon:\n"
        "  • Separated (PWj) — matches 28-byte Advertised_Data\n"
        "  • Nearby (Pi) — matches MAC_Address\n"
        "  • Latched Pi→Sep — Pi MAC match with 28-byte advertisement\n\n"
        "Results include a Source Phone column showing which phone each match came from.\n"
        "⚠  Beacons with no secondary secret fall back to the primary shared secret."
    )
    info.config(state='disabled')

    # ---- Rebuild beacon checkbox list (called whenever a phone CSV changes) -
    def _rebuild_beacon_list():
        """Rebuild the grouped checkbox list from all loaded phone records."""
        # Save existing selections BEFORE destroying anything so they survive
        # the rebuild.  Key is (phone_idx, rec_idx); value is the bool state.
        saved_selections = {(pi, ri): v.get() for pi, ri, v in check_items}

        # Destroy all existing widgets in the inner frame
        for widget in cb_inner.winfo_children():
            widget.destroy()
        check_items.clear()

        any_loaded = any(len(phone_records[i]) > 0 for i in range(NUM_PHONES))
        if not any_loaded:
            placeholder_lbl2 = tk.Label(
                cb_inner,
                text="Load an OwnedBeacons CSV above to populate this list.",
                font=('Helvetica', 9), fg=_ph_fg, bg=_frame_bg, pady=12)
            placeholder_lbl2.pack()
            _update_count()
            sel_all_btn.config(state='disabled')
            desel_all_btn.config(state='disabled')
            return

        global_rec_idx = 0
        for phone_idx in range(NUM_PHONES):
            recs = phone_records[phone_idx]
            if not recs:
                continue

            fname = Path(phone_full_paths[phone_idx]).name if phone_full_paths[phone_idx] else ''
            custom_name = phone_name_vars[phone_idx].get().strip()
            display_name = custom_name if custom_name else f"Phone {phone_idx + 1}"
            header_text = f"{display_name}  —  {fname}" if fname else display_name

            # Phone group header
            hdr_f = tk.Frame(cb_inner, bg=_hdr_bg)
            hdr_f.pack(fill='x', pady=(4, 1))
            tk.Label(hdr_f, text=f"  {header_text}",
                     font=('Helvetica', 9, 'bold'),
                     bg=_hdr_bg, fg=_hdr_fg,
                     anchor='w', pady=3).pack(fill='x')

            for rec_idx, rec in enumerate(recs):
                lbl_text = _build_beacon_label(rec)
                # Restore saved selection if this beacon existed before the
                # rebuild; otherwise default to True (all-checked) so that
                # newly loaded phones start fully selected.
                checked = saved_selections.get((phone_idx, rec_idx), True)
                var = tk.BooleanVar(value=checked)
                check_items.append((phone_idx, rec_idx, var))

                cb = tk.Checkbutton(
                    cb_inner,
                    text=f"    {lbl_text}",   # indent under phone header
                    variable=var,
                    command=_update_count,
                    font=('Helvetica', 10),
                    anchor='w',
                    padx=6,
                    bg=_frame_bg,
                    fg=_entry_fg,
                    selectcolor=_entry_bg,
                    activebackground=_frame_bg,
                    activeforeground=_entry_fg,
                )
                cb.pack(fill='x', pady=1)
                cb.bind('<MouseWheel>', _on_mousewheel)
                global_rec_idx += 1

        _update_count()
        sel_all_btn.config(state='normal')
        desel_all_btn.config(state='normal')

    # ---- Load beacons for a specific phone slot ----------------------------
    def _load_phone_beacons(phone_idx: int, path: str):
        try:
            new_records = load_owned_beacons_csv(path)
        except ValueError as exc:
            messagebox.showerror("Cannot Read OwnedBeacons CSV", str(exc),
                                 parent=dlg)
            phone_status_vars[phone_idx].set("⚠ Error reading file — see message above")
            if phone_status_lbls[phone_idx]:
                phone_status_lbls[phone_idx].config(fg='#cc0000')
            return
        except Exception as exc:
            messagebox.showerror("Error",
                                 f"Unexpected error reading OwnedBeacons CSV:\n{exc}",
                                 parent=dlg)
            phone_status_vars[phone_idx].set("⚠ Unexpected error")
            if phone_status_lbls[phone_idx]:
                phone_status_lbls[phone_idx].config(fg='#cc0000')
            return

        if not new_records:
            messagebox.showwarning(
                "No Usable Beacons",
                "The selected CSV contained no beacon rows with a Public_Key_Hex.\n\n"
                "Please check that the file is a Lost Apples OwnedBeacons export "
                "and that key material was extracted during processing.",
                parent=dlg
            )
            phone_status_vars[phone_idx].set("⚠ No usable beacon rows found")
            if phone_status_lbls[phone_idx]:
                phone_status_lbls[phone_idx].config(fg='#cc0000')
            return

        # Store results
        phone_records[phone_idx]   = new_records
        phone_full_paths[phone_idx] = path
        phone_path_vars[phone_idx].set(Path(path).name)
        phone_status_vars[phone_idx].set(f"✓ {len(new_records)} beacon(s) loaded")
        if phone_status_lbls[phone_idx]:
            phone_status_lbls[phone_idx].config(fg='#2a7a2a')

        try:
            app._log(f"  CSV Compare: Phone {phone_idx + 1} — loaded "
                     f"{len(new_records)} beacon(s) from {Path(path).name}")
        except Exception:
            pass

        _rebuild_beacon_list()

    # ---- Run Comparison callback -------------------------------------------
    def on_run():
        # At least Phone 1 must be loaded
        if not phone_records[0]:
            messagebox.showwarning(
                "No Beacons Loaded",
                "Please load at least one OwnedBeacons CSV (Phone 1) before running.",
                parent=dlg
            )
            return

        obs_full = _browse_obs._full_path
        if not obs_full:
            messagebox.showwarning(
                "No Observations CSV",
                "Please select an Observations.db CSV export before running.",
                parent=dlg
            )
            return

        # Gather selected (phone_idx, record) pairs, with human-readable label
        selected_with_phone: List[Tuple[str, CsvBeaconRecord]] = []
        for phone_idx, rec_idx, var in check_items:
            if var.get():
                custom_name = phone_name_vars[phone_idx].get().strip()
                label = custom_name if custom_name else f"Phone {phone_idx + 1}"
                selected_with_phone.append((label, phone_records[phone_idx][rec_idx]))

        if not selected_with_phone:
            messagebox.showwarning(
                "No Beacon Selected",
                "Please select at least one beacon before comparing.",
                parent=dlg
            )
            return

        # Validate each selected record
        bad_keys = [(lbl, r) for lbl, r in selected_with_phone if not r.public_key_hex]
        if bad_keys:
            names = ', '.join(f"{lbl}/{r.custom_name or str(r.identifier or '?')[:8]}"
                              for lbl, r in bad_keys)
            messagebox.showerror(
                "Missing Public Key",
                f"The following beacon(s) have no Public_Key_Hex and will be "
                f"skipped:\n  {names}\n\nPlease deselect them or re-export the "
                "OwnedBeacons CSV with key material extracted.",
                parent=dlg
            )
            selected_with_phone = [(lbl, r) for lbl, r in selected_with_phone
                                   if r.public_key_hex]
            if not selected_with_phone:
                return

        no_secrets = [(lbl, r) for lbl, r in selected_with_phone
                      if not r.shared_secret_hex and not r.secondary_shared_secret_hex]
        if no_secrets:
            names = ', '.join(f"{lbl}/{r.custom_name or str(r.identifier or '?')[:8]}"
                              for lbl, r in no_secrets)
            messagebox.showerror(
                "Missing Shared Secrets",
                f"The following beacon(s) have no shared secret fields and "
                f"cannot be compared:\n  {names}",
                parent=dlg
            )
            selected_with_phone = [(lbl, r) for lbl, r in selected_with_phone
                                   if r.shared_secret_hex or r.secondary_shared_secret_hex]
            if not selected_with_phone:
                return

        no_date = [(lbl, r) for lbl, r in selected_with_phone if not r.pairing_date]
        if no_date:
            names = ', '.join(f"{lbl}/{r.custom_name or str(r.identifier or '?')[:8]}"
                              for lbl, r in no_date)
            messagebox.showerror(
                "Missing Pairing Date",
                f"The following beacon(s) have no Pairing_Date and cannot be "
                f"compared:\n  {names}",
                parent=dlg
            )
            selected_with_phone = [(lbl, r) for lbl, r in selected_with_phone
                                   if r.pairing_date]
            if not selected_with_phone:
                return

        # Warn once if any selected beacon lacks a secondary secret
        no_secondary = [(lbl, r) for lbl, r in selected_with_phone
                        if not r.secondary_shared_secret_hex]
        if no_secondary:
            names = ', '.join(f"{lbl}/{r.custom_name or str(r.identifier or '?')[:8]}"
                              for lbl, r in no_secondary)
            if not messagebox.askokcancel(
                "Separated Search Limitation",
                f"The following beacon(s) have no Secondary_Shared_Secret_Hex:\n"
                f"  {names}\n\n"
                "The separated key (PWj) search will fall back to the primary "
                "Shared_Secret_Hex for those beacons.\n"
                "This is typical for iPhone records.\n\n"
                "Continue?",
                parent=dlg
            ):
                return

        dlg.destroy()
        _run_combined_comparison(app, selected_with_phone, obs_full)

    # ---- Bottom buttons ----------------------------------------------------
    btn_row = tk.Frame(dlg, pady=10)
    btn_row.pack()

    tk.Button(btn_row,
              text="Run Comparison",
              command=on_run,
              font=('Helvetica', 10),
              padx=14, pady=4,
              cursor='hand2').pack(side='left', padx=8)

    tk.Button(btn_row,
              text="Cancel",
              command=dlg.destroy,
              font=('Helvetica', 10),
              padx=14, pady=4).pack(side='left', padx=8)
