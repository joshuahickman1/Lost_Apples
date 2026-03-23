"""
wild_mode_comparison.py
=======================
Wild Mode Beacon Comparison module for Lost Apples.

Compares a unified Wild Mode CSV export (from one device extraction) against
an OwnedBeacons CSV export (from a different device extraction) using the same
cryptographic key derivation engine as the Observations.db comparison.

Forensic Use Case
-----------------
A Wild Mode record means the beacon triggered an unwanted tracker alert on
the victim's phone.  By deriving all rolling advertisement keys for every
beacon in an OwnedBeacons CSV and matching them against the Wild Mode
advertisement data, a forensic analyst can prove that a specific registered
tracker belongs to a specific person.

Match Logic
-----------
iOS 17 records  : ``Advertisement_Hex`` is present (28 bytes / 56 hex chars).
                  Matched against the derived PWj and Pi key hex —
                  the same way Observations.db 28-byte rows are matched.

iOS 18 records  : ``Advertisement_Hex`` is absent; only ``Advertisement_MAC``
                  is present (6-byte BLE MAC, colon-separated).
                  Matched against the derived 6-byte BLE MAC address —
                  the same way short Observations.db rows are matched.

Both searches run in a single background pass via the key schedule engines
already used by csv_compare_gui.py.

Public entry points
-------------------
    validate_wild_mode_csv(path)          -> (bool, str)
    validate_owned_beacons_csv(path)      -> (bool, str)
    parse_wild_mode_for_comparison(path)  -> 5-tuple (same shape as
                                            csv_compare_gui._parse_observations_csv)
    run_wild_mode_key_comparison(app, wm_phone_paths, ob_csv_path)
"""

import csv as _csv
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Wild Mode CSV column names
# ---------------------------------------------------------------------------

WM_UUID      = 'UUID'
WM_ADV_HEX   = 'Advertisement_Hex'
WM_ADV_MAC   = 'Advertisement_MAC'
WM_FIRST_TS  = 'First_Seen_Timestamp'
WM_FIRST_LAT = 'First_Seen_Latitude'
WM_FIRST_LON = 'First_Seen_Longitude'
WM_LAST_TS   = 'Last_Seen_Timestamp'
WM_LAST_LAT  = 'Last_Seen_Latitude'
WM_LAST_LON  = 'Last_Seen_Longitude'


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read_csv(path: str) -> Tuple[List[Dict[str, str]], List[str]]:
    """
    Read a Lost Apples CSV export, skipping comment lines that begin with '#'.

    Returns (rows, fieldnames).
    """
    rows: List[Dict[str, str]] = []
    fieldnames: List[str] = []

    with open(path, newline='', encoding='utf-8', errors='replace') as fh:
        filtered = (line for line in fh if not line.startswith('#'))
        reader = _csv.DictReader(filtered)
        fieldnames = list(reader.fieldnames or [])
        for row in reader:
            rows.append(dict(row))

    return rows, fieldnames


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_wild_mode_csv(path: str) -> Tuple[bool, str]:
    """
    Confirm that *path* looks like a Lost Apples unified Wild Mode CSV.

    Returns (True, '') on success, or (False, error_message) on failure.
    """
    if not Path(path).exists():
        return False, f"File not found: {path}"

    try:
        _, fieldnames = _read_csv(path)
    except Exception as exc:
        return False, f"Could not read file: {exc}"

    # Require at least UUID and one of the two MAC/adv columns
    required = {WM_UUID, WM_ADV_MAC}
    missing = required - set(fieldnames)
    if missing:
        return False, (
            f"File does not appear to be a Wild Mode unified CSV.\n"
            f"Missing expected columns: {', '.join(sorted(missing))}\n"
            f"Found columns: {', '.join(fieldnames)}"
        )

    return True, ''


def validate_owned_beacons_csv(path: str) -> Tuple[bool, str]:
    """
    Confirm that *path* looks like a Lost Apples OwnedBeacons CSV that
    contains key material (Public_Key_Hex column).

    Returns (True, '') on success, or (False, error_message) on failure.
    """
    if not Path(path).exists():
        return False, f"File not found: {path}"

    try:
        _, fieldnames = _read_csv(path)
    except Exception as exc:
        return False, f"Could not read file: {exc}"

    # Must have both Identifier and the key material column
    required = {'Identifier', 'Public_Key_Hex'}
    missing = required - set(fieldnames)
    if missing:
        return False, (
            f"File does not appear to be a Lost Apples OwnedBeacons CSV "
            f"with key material.\n"
            f"Missing expected columns: {', '.join(sorted(missing))}\n"
            f"Found columns: {', '.join(fieldnames)}\n\n"
            "Please make sure you are loading a Lost Apples OwnedBeacons "
            "export that was produced with key extraction enabled."
        )

    return True, ''


# ---------------------------------------------------------------------------
# Wild Mode CSV parser for the key-comparison engine
# ---------------------------------------------------------------------------

def parse_wild_mode_for_comparison(csv_path: str):
    """
    Parse a unified Wild Mode CSV and return six target structures that the
    key-schedule search engines expect.

    Returns
    -------
    adv_targets      : List[(adv_hex_56, mac_str, ts)]
        One entry per Wild Mode row whose Advertisement_Hex is exactly
        28 bytes (56 hex chars).  Used by the separated key (PWj) engine
        for a direct hex comparison against derived PWj bytes.

    mac_targets      : List[(mac_str, ts)]
        One entry per unique Advertisement_MAC whose Advertisement_Hex is
        absent (iOS 18 records).  Used by the nearby (Pi) engine.
        De-duplicated by normalised MAC.

    mac_to_adv       : dict {norm_12hex_mac -> adv_hex_str}
        Maps each normalised MAC to the Advertisement_Hex for that row
        (empty string if not present).  Used for latch detection.

    mac_to_all_times : dict {norm_12hex_mac -> List[str]}
        All timestamps (First_Seen + Last_Seen) recorded for each MAC.
        Populates observation_count and all_observation_times on matches.

    adv_to_all_times : dict {adv_hex_56 -> List[str]}
        All timestamps recorded for each 28-byte advertisement.
        Populates observation_count and all_observation_times on matches.

    sep_mac_targets  : List[(mac_str, ts)]
        One entry per unique Advertisement_MAC from iOS 17 records where
        the Advertisement_Hex is present but shorter than 56 chars (i.e.
        only the 6-byte MAC portion was stored rather than the full 28-byte
        PWj).  These MACs are derived from PWj — not Pi — so they must be
        searched against the separated key schedule via search_by_ble_mac(),
        NOT against the nearby key schedule.

    Raises ValueError if the file cannot be read.
    """
    adv_targets:      list = []
    mac_targets:      list = []
    mac_to_adv:       dict = {}
    mac_to_all_times: dict = {}
    adv_to_all_times: dict = {}
    seen_macs:        set  = set()
    sep_mac_targets:  list = []
    seen_sep_macs:    set  = set()

    try:
        wm_rows, _ = _read_csv(csv_path)
    except Exception as exc:
        raise ValueError(f"Could not read Wild Mode CSV:\n{exc}")

    for row in wm_rows:
        adv_hex = row.get(WM_ADV_HEX, '').replace(' ', '').strip().lower()
        mac_str = row.get(WM_ADV_MAC, '').strip()
        first_ts = row.get(WM_FIRST_TS, '').strip()
        last_ts  = row.get(WM_LAST_TS, '').strip()

        # Primary timestamp — prefer last seen
        ts = last_ts or first_ts

        # Collect all available timestamps for this beacon
        timestamps: list = []
        if first_ts:
            timestamps.append(first_ts)
        if last_ts and last_ts != first_ts:
            timestamps.append(last_ts)
        if not timestamps and ts:
            timestamps = [ts]

        # ------------------------------------------------------------------
        # iOS 17 full-adv: 28-byte advertisement present.
        # -> separated key (PWj) exact-hex target.
        # -> also kept in mac_targets for latch-detection via Phase B.
        # ------------------------------------------------------------------
        if len(adv_hex) == 56:
            adv_targets.append((adv_hex, mac_str, ts))
            if adv_hex not in adv_to_all_times:
                adv_to_all_times[adv_hex] = []
            adv_to_all_times[adv_hex].extend(timestamps)
            # Also add MAC for latch detection (Phase B)
            if mac_str:
                norm = (mac_str.upper()
                        .replace(':', '').replace('-', '').replace(' ', ''))
                if norm not in seen_macs:
                    seen_macs.add(norm)
                    mac_targets.append((mac_str, ts))
                if norm not in mac_to_adv:
                    mac_to_adv[norm] = adv_hex
                if norm not in mac_to_all_times:
                    mac_to_all_times[norm] = []
                mac_to_all_times[norm].extend(timestamps)

        # ------------------------------------------------------------------
        # iOS 17 short-adv: Advertisement_Hex is present but only 6 bytes
        # (12 hex chars).  The parser stored only the MAC portion of PWj.
        # The MAC is PWj-derived — NOT Pi-derived — so these rows must be
        # searched against the *separated* key schedule using
        # KeyScheduleGenerator.search_by_ble_mac(), not the nearby schedule.
        # ------------------------------------------------------------------
        elif 0 < len(adv_hex) < 56 and mac_str:
            norm = (mac_str.upper()
                    .replace(':', '').replace('-', '').replace(' ', ''))
            if norm not in seen_sep_macs:
                seen_sep_macs.add(norm)
                sep_mac_targets.append((mac_str, ts))
            if norm not in mac_to_adv:
                mac_to_adv[norm] = adv_hex
            if norm not in mac_to_all_times:
                mac_to_all_times[norm] = []
            mac_to_all_times[norm].extend(timestamps)

        # ------------------------------------------------------------------
        # iOS 18: no advertisement hex — only MAC available.
        # MAC is Pi-derived; search via nearby key schedule (Phase B).
        # ------------------------------------------------------------------
        elif mac_str:
            norm = (mac_str.upper()
                    .replace(':', '').replace('-', '').replace(' ', ''))
            if norm not in seen_macs:
                seen_macs.add(norm)
                mac_targets.append((mac_str, ts))
            if norm not in mac_to_adv:
                mac_to_adv[norm] = adv_hex
            if norm not in mac_to_all_times:
                mac_to_all_times[norm] = []
            mac_to_all_times[norm].extend(timestamps)

    return adv_targets, mac_targets, mac_to_adv, mac_to_all_times, adv_to_all_times, sep_mac_targets


# ---------------------------------------------------------------------------
# Key comparison — background worker
# ---------------------------------------------------------------------------

def run_wild_mode_key_comparison(app,
                                  wm_phone_paths: List[Tuple[str, str]],
                                  ob_csv_path: str) -> None:
    """
    Compare all beacons in an OwnedBeacons CSV against one or more Wild Mode
    CSVs using the same two-phase key derivation engine as the Observations.db
    comparison.

    Phase A -- Separated key search (PWj): matches 28-byte Advertisement_Hex
    Phase B -- Nearby key search (Pi):     matches Advertisement_MAC (6-byte)

    Results are shown in the standard combined-results window from
    csv_compare_gui (colour-coded table with double-click timestamp detail
    and CSV export).  The Source Phone column shows which Wild Mode CSV
    contributed each matched observation.

    Parameters
    ----------
    app             : SearchpartydGUI -- must have .root and ._log()
    wm_phone_paths  : list of (phone_label, path) tuples, e.g.
                      [('Phone 1', '/path/wm1.csv'), ('Phone 2', '/path/wm2.csv')]
    ob_csv_path     : path to the OwnedBeacons CSV export (with key material)
    """
    from src.csv_compare_gui import (
        load_owned_beacons_csv,
        CombinedMatch,
        _show_combined_results,
    )
    from src.key_schedule_generator import (
        KeyScheduleGenerator,
        NearbyKeyScheduleGenerator,
    )

    # ---- Parse and merge all Wild Mode CSVs ----------------------------------
    # adv_to_phones / mac_to_phones track which phone(s) each target came from
    # so we can stamp source_phone on every match.
    adv_targets:      list = []
    mac_targets:      list = []
    mac_to_adv:       dict = {}
    mac_to_all_times: dict = {}
    adv_to_all_times: dict = {}
    adv_to_phones:      dict = {}   # {adv_hex_56 -> set of phone_label}
    mac_to_phones:      dict = {}   # {norm_12hex_mac -> set of phone_label}
    sep_mac_to_phones:  dict = {}   # {norm_12hex_mac -> set of phone_label}  iOS 17 PWj-MAC targets
    seen_macs_global:   set  = set()
    sep_mac_targets:    list = []   # 6-byte PWj-derived MACs from iOS 17 records
    seen_sep_global:    set  = set()

    for phone_label, wm_path in wm_phone_paths:
        try:
            (p_adv, p_mac, p_mac_to_adv,
             p_mac_to_all_times, p_adv_to_all_times,
             p_sep_mac) = \
                parse_wild_mode_for_comparison(wm_path)
        except ValueError as exc:
            messagebox.showerror(
                "Wild Mode CSV Error",
                f"{phone_label}: {exc}",
                parent=app.root
            )
            return

        # Merge 28-byte adv targets
        for entry in p_adv:
            adv_hex = entry[0]
            adv_targets.append(entry)
            adv_to_phones.setdefault(adv_hex, set()).add(phone_label)

        # Merge adv_to_all_times
        for adv_hex, times in p_adv_to_all_times.items():
            adv_to_all_times.setdefault(adv_hex, []).extend(times)

        # Merge MAC targets (iOS 18 / Pi-derived) — de-dup globally
        for mac_str, ts in p_mac:
            norm = (mac_str.upper()
                    .replace(':', '').replace('-', '').replace(' ', ''))
            if norm not in seen_macs_global:
                seen_macs_global.add(norm)
                mac_targets.append((mac_str, ts))
            mac_to_phones.setdefault(norm, set()).add(phone_label)

        # Merge separated-MAC targets (iOS 17 / PWj-derived) — de-dup globally
        for mac_str, ts in p_sep_mac:
            norm = (mac_str.upper()
                    .replace(':', '').replace('-', '').replace(' ', ''))
            if norm not in seen_sep_global:
                seen_sep_global.add(norm)
                sep_mac_targets.append((mac_str, ts))
            sep_mac_to_phones.setdefault(norm, set()).add(phone_label)

        # Merge mac_to_adv (first occurrence wins)
        for norm, adv in p_mac_to_adv.items():
            mac_to_adv.setdefault(norm, adv)

        # Merge mac_to_all_times
        for norm, times in p_mac_to_all_times.items():
            mac_to_all_times.setdefault(norm, []).extend(times)

        try:
            p_adv_u = len({e[0] for e in p_adv})
            app._log(
                f"  Wild Mode Compare ({phone_label}): "
                f"{p_adv_u} unique 28-byte adv rows, "
                f"{len(p_mac)} nearby MACs, "
                f"{len(p_sep_mac)} separated MACs "
                f"from {Path(wm_path).name}"
            )
        except Exception:
            pass

    # ---- Load OwnedBeacons ------------------------------------------------
    try:
        records = load_owned_beacons_csv(ob_csv_path)
    except ValueError as exc:
        messagebox.showerror("OwnedBeacons CSV Error", str(exc), parent=app.root)
        return

    if not records:
        messagebox.showwarning(
            "No Usable Beacons",
            "The OwnedBeacons CSV contained no beacon rows with key material.\n\n"
            "Please ensure the file was exported with key extraction enabled.",
            parent=app.root
        )
        return

    if not adv_targets and not mac_targets and not sep_mac_targets:
        messagebox.showwarning(
            "No Wild Mode Targets",
            "The Wild Mode CSV(s) contained no usable rows.\n\n"
            "Please check that the files are Lost Apples unified Wild Mode exports.",
            parent=app.root
        )
        return

    # ---- Progress window --------------------------------------------------
    total_beacons = len(records)
    prog_win = tk.Toplevel(app.root)
    prog_win.title("Wild Mode Comparison \u2014 Deriving Keys\u2026")
    prog_win.geometry("420x150")
    prog_win.resizable(False, False)
    prog_win.transient(app.root)

    tk.Label(prog_win,
             text="Searching separated and nearby key chains\u2026",
             font=('Helvetica', 11)).pack(pady=(16, 6))
    pb = ttk.Progressbar(prog_win, length=360, mode='determinate')
    pb.pack(padx=30)
    phase_lbl = tk.Label(prog_win,
                          text=f"Beacon 1 of {total_beacons}: Separated keys\u2026",
                          font=('Helvetica', 9))
    phase_lbl.pack(pady=(4, 0))
    status_lbl = tk.Label(prog_win, text="Starting\u2026", font=('Helvetica', 8),
                           fg='#555555')
    status_lbl.pack()

    results_holder = [None]
    error_holder   = [None]

    beacon_share = 100.0 / total_beacons

    def make_progress_callbacks(beacon_idx: int):
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
            for beacon_idx, record in enumerate(records):
                pub_key = bytes.fromhex(record.public_key_hex)
                pairing = record.pairing_date

                d0 = bytes.fromhex(record.private_scalar_hex) \
                     if record.private_scalar_hex else None

                bid   = str(record.identifier or 'Unknown')
                bname = record.custom_name or bid[:8]

                _today = datetime.now()
                if pairing and pairing < _today:
                    SEP_MAX  = max(1, (_today - pairing).days + 7)
                    NEAR_MAX = max(1, int((_today - pairing).total_seconds() / 900) + 96)
                else:
                    SEP_MAX  = 3000
                    NEAR_MAX = 105120

                try:
                    app._log(f"  [{bname}] Key range: {SEP_MAX} day(s) separated / "
                             f"{NEAR_MAX} step(s) nearby")
                except Exception:
                    pass

                progress_sep, progress_near = make_progress_callbacks(beacon_idx)

                # ----------------------------------------------------------
                # Phase A: Separated key search (PWj)
                #   A-1: exact 28-byte PWj hex match (iOS 17 full-adv records)
                #   A-2: 6-byte BLE MAC match (iOS 17 short-adv records where
                #        only the first 6 bytes of PWj were stored)
                # ----------------------------------------------------------
                sep_secret = (record.secondary_shared_secret_hex
                              or record.shared_secret_hex)

                if sep_secret and (adv_targets or sep_mac_targets):
                    set_phase(f"Beacon {beacon_idx + 1}/{total_beacons}: "
                              f"Separated keys (PWj)\u2026")
                    sks0    = bytes.fromhex(sep_secret)
                    sep_gen = KeyScheduleGenerator(pub_key, sks0, pairing, d0=d0)

                    # A-1: exact PWj hex match
                    if adv_targets:
                        sep_matches = sep_gen.search_observations(
                            adv_targets,
                            max_days=SEP_MAX,
                            progress_callback=progress_sep,
                        )
                        for m in sep_matches:
                            adv_hex   = m.pw_j_bytes.hex()
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
                            cm.observation_count     = len(adv_times)
                            cm.all_observation_times = adv_times
                            cm.beacon_id             = bid
                            cm.beacon_name           = bname
                            cm.source_phone          = ', '.join(
                                sorted(adv_to_phones.get(adv_hex, {'?'})))
                            combined.append(cm)

                    # A-2: PWj BLE MAC match — iOS 17 records where the plist
                    # only stored 6 bytes (address.data) with no full advertisement.
                    # The MAC is the first 6 bytes of PWj with | 0xC0 applied.
                    if sep_mac_targets:
                        sep_mac_matches = sep_gen.search_by_ble_mac(
                            sep_mac_targets,
                            max_days=SEP_MAX,
                            progress_callback=progress_sep,
                        )
                        for m in sep_mac_matches:
                            norm_mac = (m.observed_mac.upper()
                                        .replace(':', '').replace('-', '').replace(' ', ''))
                            all_times = mac_to_all_times.get(norm_mac, [m.observed_time])
                            cm = CombinedMatch(
                                match_type         = 'Separated_Key',
                                key_index          = m.day_index,
                                estimated_date_str = m.estimated_date_str,
                                derived_ble_str    = m.ble_address_str,
                                key_hex            = m.pw_j_bytes.hex(),
                                observed_mac       = m.observed_mac,
                                observed_time      = m.observed_time,
                                adv_data_hex       = m.pw_j_bytes.hex(),
                            )
                            cm.observation_count     = len(all_times)
                            cm.all_observation_times = all_times
                            cm.beacon_id             = bid
                            cm.beacon_name           = bname
                            cm.source_phone          = ', '.join(
                                sorted(sep_mac_to_phones.get(norm_mac, {'?'})))
                            combined.append(cm)
                else:
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

                # ----------------------------------------------------------
                # Phase B: Nearby key search (Pi) -- MAC targets
                # ----------------------------------------------------------
                if record.shared_secret_hex and mac_targets:
                    set_phase(f"Beacon {beacon_idx + 1}/{total_beacons}: "
                              f"Nearby keys (Pi)\u2026")
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
                        cm.observation_count     = len(all_times)
                        cm.all_observation_times = all_times
                        cm.beacon_id             = bid
                        cm.beacon_name           = bname
                        cm.source_phone          = ', '.join(
                            sorted(mac_to_phones.get(norm_mac, {'?'})))
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
                messagebox.showerror(
                    "Wild Mode Comparison Error",
                    f"Comparison failed:\n{error_holder[0]}",
                    parent=app.root
                )
                try:
                    app._log(f"  \u2717 Wild Mode comparison error: {error_holder[0]}", "error")
                except Exception:
                    pass
            elif results_holder[0] is not None:
                _show_combined_results(
                    app,
                    [('', r) for r in records],
                    results_holder[0],
                    wm_phone_paths[0][1],
                    mode="wild_mode",
                )

    app.root.after(100, check)
