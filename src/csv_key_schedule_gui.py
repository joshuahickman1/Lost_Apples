"""
csv_key_schedule_gui.py
=======================
Unified key schedule dialog for Lost Apples.

Lets an examiner load a previously-exported OwnedBeacons CSV (produced by
the "Export Results" → OwnedBeacons option), pick a beacon from that file,
choose Separated or Nearby key type, set parameters, and generate the key
schedule table.

  • Generate Schedule — display the daily (Separated) or 15-minute (Nearby)
    BLE advertisement key table

This dialog is always enabled — no extraction processing is required first.
It is the replacement for the two separate "Calculate Separated Keys" and
"Calculate Nearby Keys" buttons that required a prior extraction run.

HOW IT WORKS (for beginners)
-----------------------------
1. The user browses to an OwnedBeacons CSV that Lost Apples exported earlier.
2. This file is parsed into a list of lightweight "mock record" objects.
   Each mock record holds the same fields (public_key_hex, shared_secret_hex,
   etc.) that the key schedule generators expect — so we can reuse all the
   existing generation and comparison logic without any changes to those files.
3. The user picks a beacon, chooses Separated or Nearby, sets parameters,
   and clicks Generate Schedule.
4. The existing backend generators (KeyScheduleGenerator for Separated,
   NearbyKeyScheduleGenerator for Nearby) do all the cryptographic work.
   This file only handles the UI.
"""

import csv
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime, timedelta
from pathlib import Path


# ---------------------------------------------------------------------------
# Public entry point — called from searchpartyd_gui.py
# ---------------------------------------------------------------------------

def show_key_schedule_from_csv_dialog(app) -> None:
    """
    Open the unified key schedule dialog.

    Parameters
    ----------
    app : SearchpartydGUI instance — provides app.root and app._log()
    """
    _open_main_dialog(app)


# ---------------------------------------------------------------------------
# Mock record — mimics OwnedBeaconRecord field names
# ---------------------------------------------------------------------------

class _MockBeaconRecord:
    """
    Lightweight stand-in for an OwnedBeaconRecord.

    The key schedule generators only access these specific attributes, so
    this class only needs to provide them.  No cryptographic logic here.
    """
    __slots__ = (
        'identifier', 'model', 'custom_name', 'emoji', 'pairing_date',
        'public_key_hex', 'private_scalar_hex',
        'shared_secret_hex', 'secondary_shared_secret_hex',
    )

    def __init__(self):
        self.identifier                    = None
        self.model                         = None
        self.custom_name                   = None
        self.emoji                         = None
        self.pairing_date                  = None   # datetime or None
        self.public_key_hex                = None
        self.private_scalar_hex            = None
        self.shared_secret_hex             = None
        self.secondary_shared_secret_hex   = None


# ---------------------------------------------------------------------------
# CSV parsing
# ---------------------------------------------------------------------------

# Date formats that Lost Apples writes when it serialises a Python datetime to
# a CSV cell via str() or csv.writer's default str conversion.
_DATE_FORMATS = [
    '%Y-%m-%d %H:%M:%S.%f',   # 2023-05-14 12:34:56.000000
    '%Y-%m-%d %H:%M:%S',      # 2023-05-14 12:34:56
    '%Y-%m-%dT%H:%M:%S.%f',   # ISO 8601 with microseconds
    '%Y-%m-%dT%H:%M:%S',      # ISO 8601
    '%Y-%m-%d',               # date only
]


def _parse_date(raw: str) -> datetime | None:
    """Try each known format; return a datetime or None."""
    raw = raw.strip()
    if not raw:
        return None
    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(raw, fmt)
        except ValueError:
            continue
    return None


def _parse_owned_beacons_csv(path: str) -> list[_MockBeaconRecord]:
    """
    Read an OwnedBeacons CSV and return a list of _MockBeaconRecord objects.

    Skips rows that are missing the Public_Key_Hex column (required for any
    key derivation).  Rows missing both shared secrets are kept but will be
    filtered later when the user selects a key type.
    """
    records = []
    required_cols = {'Public_Key_Hex'}
    # Columns we care about — all others are silently ignored
    col_map = {
        'Identifier':                   'identifier',
        'Model':                        'model',
        'Custom_Name':                  'custom_name',
        'Emoji':                        'emoji',
        'Pairing_Date':                 'pairing_date',
        'Public_Key_Hex':               'public_key_hex',
        'Private_Scalar_Hex':           'private_scalar_hex',
        'Shared_Secret_Hex':            'shared_secret_hex',
        'Secondary_Shared_Secret_Hex':  'secondary_shared_secret_hex',
    }

    with open(path, newline='', encoding='utf-8', errors='replace') as fh:
        # Skip comment lines that Lost Apples prepends (lines starting with #)
        lines = [l for l in fh if not l.startswith('#')]

    reader = csv.DictReader(lines)

    # Verify the file has at least the required columns
    if reader.fieldnames is None:
        raise ValueError("The selected file appears to be empty.")
    missing = required_cols - set(reader.fieldnames)
    if missing:
        raise ValueError(
            f"The selected file is missing required column(s): "
            f"{', '.join(sorted(missing))}\n\n"
            "Please select a file exported by Lost Apples using "
            "Export Results → OwnedBeacons."
        )

    for row in reader:
        pub = row.get('Public_Key_Hex', '').strip()
        if not pub:
            continue   # skip rows with no public key

        rec = _MockBeaconRecord()
        for csv_col, attr in col_map.items():
            val = row.get(csv_col, '').strip()
            if attr == 'pairing_date':
                setattr(rec, attr, _parse_date(val))
            else:
                setattr(rec, attr, val if val else None)
        records.append(rec)

    return records


# ---------------------------------------------------------------------------
# Helper — build a human-readable label for each beacon
# ---------------------------------------------------------------------------

def _beacon_label(rec: _MockBeaconRecord) -> str:
    name  = rec.custom_name or ''
    emoji = rec.emoji or ''
    uid   = str(rec.identifier or 'Unknown')
    short = uid[:8] + '…'
    if name and emoji:
        return f"{emoji} {name}  [{short}]"
    if name:
        return f"{name}  [{short}]"
    if rec.model:
        return f"{rec.model}  [{short}]"
    return f"[{short}]"


# ---------------------------------------------------------------------------
# Main dialog
# ---------------------------------------------------------------------------

def _open_main_dialog(app) -> None:
    """
    The single unified key schedule dialog.

    Layout
    ------
    ┌─ Header ────────────────────────────────────────────────┐
    │  Title + subtitle                                        │
    ├─ Body ──────────────────────────────────────────────────┤
    │  1.  OwnedBeacons CSV  [Browse…]  <path label>          │
    │  2.  Beacon:           [dropdown]                        │
    │  3.  Key type:         ◉ Separated   ○ Nearby           │
    │  4a. (Separated)  Start date / End date                  │
    │  4b. (Nearby)     Days to generate                       │
    │      Pairing date display (read-only)                    │
    ├─ Buttons ───────────────────────────────────────────────┤
    │  [Generate Schedule]  [Cancel]                           │
    └─────────────────────────────────────────────────────────┘
    """
    dlg = tk.Toplevel(app.root)
    dlg.title("Generate Key Schedule — Lost Apples")
    dlg.geometry("580x560")
    dlg.resizable(False, False)
    dlg.transient(app.root)
    dlg.grab_set()

    # Centre on parent
    dlg.update_idletasks()
    px = app.root.winfo_rootx() + (app.root.winfo_width()  - 580) // 2
    py = app.root.winfo_rooty() + (app.root.winfo_height() - 560) // 2
    dlg.geometry(f'+{px}+{py}')

    # ── State ────────────────────────────────────────────────────────────────
    records: list[_MockBeaconRecord] = []   # populated after CSV load
    beacon_labels: list[str] = []

    csv_path_var   = tk.StringVar(value='No file selected')
    beacon_var     = tk.StringVar()
    key_type_var   = tk.StringVar(value='separated')   # 'separated' | 'nearby'

    # Separated parameters
    start_var = tk.StringVar(
        value=(datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d'))
    end_var   = tk.StringVar(value=datetime.now().strftime('%Y-%m-%d'))

    # Nearby parameters
    days_var    = tk.StringVar(value='7')

    # ── Header ───────────────────────────────────────────────────────────────
    hdr = tk.Frame(dlg, bg='#1e3a5f', pady=10)
    hdr.pack(fill='x')
    tk.Label(hdr, text="FindMy Key Schedule Generator",
             bg='#1e3a5f', fg='white',
             font=('Helvetica', 13, 'bold')).pack()
    tk.Label(hdr,
             text="Load an OwnedBeacons CSV export, choose a beacon and key type, "
                  "then generate the key schedule",
             bg='#1e3a5f', fg='#aac4e0',
             font=('Helvetica', 9)).pack()

    # ── Body ─────────────────────────────────────────────────────────────────
    body = tk.Frame(dlg, padx=20, pady=14)
    body.pack(fill='both', expand=True)
    body.columnconfigure(1, weight=1)

    row = 0  # track grid row counter

    # ── Section 1: CSV file picker ──────────────────────────────────────────
    tk.Label(body, text="OwnedBeacons CSV:",
             font=('Helvetica', 10, 'bold'), anchor='w'
             ).grid(row=row, column=0, sticky='w', pady=(0, 4))

    file_frame = tk.Frame(body)
    file_frame.grid(row=row, column=1, sticky='ew', pady=(0, 4), padx=(8, 0))
    file_frame.columnconfigure(0, weight=1)

    file_lbl = tk.Label(file_frame, textvariable=csv_path_var,
                        font=('Helvetica', 9), fg='#666666',
                        anchor='w', wraplength=320, justify='left')
    file_lbl.grid(row=0, column=0, sticky='ew')

    row += 1

    def browse_csv():
        path = filedialog.askopenfilename(
            parent=dlg,
            title="Select OwnedBeacons CSV export",
            filetypes=[('CSV files', '*.csv'), ('All files', '*.*')],
        )
        if not path:
            return
        _load_csv(path)

    browse_btn = tk.Button(body, text="Browse…", command=browse_csv,
                           font=('Helvetica', 9), padx=6, pady=2,
                           cursor='hand2')
    browse_btn.grid(row=row - 1, column=1, sticky='e', pady=(0, 4),
                    padx=(8, 0))

    tk.Label(body,
             text="Export from Lost Apples using Export Results → OwnedBeacons.",
             font=('Helvetica', 8), fg='#888888'
             ).grid(row=row, column=0, columnspan=2, sticky='w', pady=(0, 10))
    row += 1

    # Thin separator
    ttk.Separator(body, orient='horizontal').grid(
        row=row, column=0, columnspan=2, sticky='ew', pady=(0, 10))
    row += 1

    # ── Section 2: Beacon selector ──────────────────────────────────────────
    tk.Label(body, text="Beacon:",
             font=('Helvetica', 10, 'bold'), anchor='w'
             ).grid(row=row, column=0, sticky='w', pady=5)

    beacon_menu = ttk.Combobox(body, textvariable=beacon_var,
                               values=[], state='disabled', width=46)
    beacon_menu.grid(row=row, column=1, sticky='ew', pady=5, padx=(8, 0))
    row += 1

    # ── Section 3: Key type ─────────────────────────────────────────────────
    tk.Label(body, text="Key type:",
             font=('Helvetica', 10, 'bold'), anchor='w'
             ).grid(row=row, column=0, sticky='w', pady=5)

    type_frame = tk.Frame(body)
    type_frame.grid(row=row, column=1, sticky='w', pady=5, padx=(8, 0))

    sep_rb = tk.Radiobutton(type_frame, text="Separated  (daily, 24-hour rotation — PWj)",
                            variable=key_type_var, value='separated',
                            font=('Helvetica', 9), command=lambda: _on_type_change())
    sep_rb.pack(anchor='w')

    nby_rb = tk.Radiobutton(type_frame, text="Nearby  (15-minute rotation — Pi)",
                            variable=key_type_var, value='nearby',
                            font=('Helvetica', 9), command=lambda: _on_type_change())
    nby_rb.pack(anchor='w')
    row += 1

    # ── Section 4a: Separated parameters ───────────────────────────────────
    sep_param_frame = tk.Frame(body)
    sep_param_frame.columnconfigure(1, weight=1)

    tk.Label(sep_param_frame, text="Start date:",
             font=('Helvetica', 10, 'bold'), anchor='w'
             ).grid(row=0, column=0, sticky='w', pady=4)
    tk.Entry(sep_param_frame, textvariable=start_var, width=18,
             font=('Courier', 10)).grid(row=0, column=1, sticky='w',
                                        pady=4, padx=(8, 0))

    tk.Label(sep_param_frame, text="End date:",
             font=('Helvetica', 10, 'bold'), anchor='w'
             ).grid(row=1, column=0, sticky='w', pady=4)
    tk.Entry(sep_param_frame, textvariable=end_var, width=18,
             font=('Courier', 10)).grid(row=1, column=1, sticky='w',
                                        pady=4, padx=(8, 0))

    tk.Label(sep_param_frame,
             text="Dates in YYYY-MM-DD format.  Keys activate at 4:00 AM local each day.",
             font=('Helvetica', 8), fg='#888888'
             ).grid(row=2, column=0, columnspan=2, sticky='w', pady=(0, 4))

    sep_param_frame.grid(row=row, column=0, columnspan=2, sticky='ew')
    row += 1

    # ── Section 4b: Nearby parameters (hidden until nearby selected) ────────
    nby_param_frame = tk.Frame(body)
    nby_param_frame.columnconfigure(1, weight=1)

    tk.Label(nby_param_frame, text="Days to generate:",
             font=('Helvetica', 10, 'bold'), anchor='w'
             ).grid(row=0, column=0, sticky='w', pady=4)
    tk.Entry(nby_param_frame, textvariable=days_var, width=8,
             font=('Courier', 10)).grid(row=0, column=1, sticky='w',
                                        pady=4, padx=(8, 0))

    tk.Label(nby_param_frame,
             text="Each day = 96 keys (one per 15 min).  7 days = 672 keys.",
             font=('Helvetica', 8), fg='#888888'
             ).grid(row=1, column=0, columnspan=2, sticky='w', pady=(0, 2))

    pairing_lbl = tk.Label(nby_param_frame, text='Pairing date: —',
                           font=('Helvetica', 8), fg='#888888', anchor='w')
    pairing_lbl.grid(row=2, column=0, columnspan=2, sticky='w', pady=(0, 4))

    # Start hidden — only shown when key_type_var == 'nearby'
    # (sep_param_frame is shown by default)

    # ── Key-type toggle logic ───────────────────────────────────────────────
    def _on_type_change():
        if key_type_var.get() == 'separated':
            nby_param_frame.grid_remove()
            sep_param_frame.grid()
        else:
            sep_param_frame.grid_remove()
            nby_param_frame.grid()
        _refresh_pairing_label()

    def _refresh_pairing_label():
        """Update the pairing date read-out when beacon or type changes."""
        if not records or not beacon_var.get():
            pairing_lbl.config(text='Pairing date: —')
            return
        try:
            idx = beacon_labels.index(beacon_var.get())
        except ValueError:
            pairing_lbl.config(text='Pairing date: —')
            return
        rec = records[idx]
        if rec.pairing_date:
            pd_str = rec.pairing_date.strftime('%Y-%m-%d %H:%M')
            pairing_lbl.config(
                text=f"Pairing date (step 1 anchor — ESTIMATED): {pd_str}")
        else:
            pairing_lbl.config(text='Pairing date: not available in CSV')

    beacon_menu.bind('<<ComboboxSelected>>', lambda e: _refresh_pairing_label())

    # ── CSV load callback ───────────────────────────────────────────────────
    def _load_csv(path: str):
        nonlocal records, beacon_labels
        try:
            loaded = _parse_owned_beacons_csv(path)
        except Exception as exc:
            messagebox.showerror("CSV Load Error",
                                 f"Could not read OwnedBeacons CSV:\n{exc}",
                                 parent=dlg)
            return

        if not loaded:
            messagebox.showwarning(
                "No Records Found",
                "The selected CSV contained no rows with a Public_Key_Hex value.\n\n"
                "Please select a file exported by Lost Apples using "
                "Export Results → OwnedBeacons.",
                parent=dlg
            )
            return

        records = loaded
        beacon_labels = [_beacon_label(r) for r in records]

        # Update UI
        short_path = Path(path).name
        csv_path_var.set(short_path)
        file_lbl.config(fg='#222222')

        beacon_menu.config(values=beacon_labels, state='readonly')
        beacon_var.set(beacon_labels[0])
        beacon_menu.current(0)

        _refresh_pairing_label()
        _log(app, f"  Loaded {len(records)} beacon record(s) from {short_path}")

    # ── Buttons ─────────────────────────────────────────────────────────────
    btn_row = tk.Frame(dlg, pady=12)
    btn_row.pack()

    def _get_record() -> _MockBeaconRecord | None:
        """Return the selected record, or None if nothing is loaded."""
        if not records or not beacon_var.get():
            messagebox.showwarning("No Beacon Selected",
                                   "Please load an OwnedBeacons CSV first.",
                                   parent=dlg)
            return None
        try:
            return records[beacon_labels.index(beacon_var.get())]
        except ValueError:
            return None

    def on_generate():
        rec = _get_record()
        if rec is None:
            return
        key_type = key_type_var.get()

        # Validate required fields
        if not rec.public_key_hex:
            messagebox.showerror("Missing Public Key",
                                 "This beacon has no Public_Key_Hex value.",
                                 parent=dlg)
            return

        if key_type == 'separated':
            if not rec.secondary_shared_secret_hex and not rec.shared_secret_hex:
                messagebox.showerror(
                    "Missing Shared Secret",
                    "This beacon has neither a Secondary_Shared_Secret_Hex nor a\n"
                    "Shared_Secret_Hex — separated key derivation is not possible.",
                    parent=dlg)
                return
            if not rec.pairing_date:
                messagebox.showerror("Missing Pairing Date",
                                     "A pairing date is required to anchor the key schedule.",
                                     parent=dlg)
                return
            try:
                start_dt = datetime.strptime(start_var.get().strip(), '%Y-%m-%d')
                end_dt   = datetime.strptime(end_var.get().strip(), '%Y-%m-%d')
            except ValueError:
                messagebox.showerror("Invalid Date",
                                     "Please enter dates in YYYY-MM-DD format.",
                                     parent=dlg)
                return
            if start_dt > end_dt:
                messagebox.showerror("Invalid Range",
                                     "Start date must be on or before end date.",
                                     parent=dlg)
                return
            dlg.destroy()
            _run_separated_generation(app, rec, start_dt, end_dt)

        else:  # nearby
            if not rec.shared_secret_hex:
                messagebox.showerror(
                    "Missing Shared Secret",
                    "This beacon has no Shared_Secret_Hex (SKN0) — "
                    "nearby key derivation is not possible.",
                    parent=dlg)
                return
            if not rec.pairing_date:
                messagebox.showerror("Missing Pairing Date",
                                     "A pairing date is required to anchor the key schedule.",
                                     parent=dlg)
                return
            try:
                days = int(days_var.get().strip())
                if days < 1 or days > 3650:
                    raise ValueError
            except ValueError:
                messagebox.showerror("Invalid Days",
                                     "Days must be a whole number between 1 and 3,650.",
                                     parent=dlg)
                return
            dlg.destroy()
            _run_nearby_generation(app, rec, days * 96)   # 96 steps per day

    tk.Button(btn_row, text="Generate Schedule", command=on_generate,
              font=('Helvetica', 10), padx=12, pady=4,
              cursor='hand2').pack(side='left', padx=6)

    tk.Button(btn_row, text="Cancel", command=dlg.destroy,
              font=('Helvetica', 10), padx=12, pady=4).pack(side='left', padx=6)

    # Show separated params by default (matching the default radio selection)
    _on_type_change()


# ---------------------------------------------------------------------------
# Separated key generation — background thread + progress window
# ---------------------------------------------------------------------------

def _run_separated_generation(app, record, start_dt: datetime,
                               end_dt: datetime) -> None:
    """Generate separated-state (PWj) keys in a background thread."""
    from src.key_schedule_generator import KeyScheduleGenerator

    prog_win   = _make_progress_window(app, "Generating Key Schedule…",
                                       "Computing separated advertisement keys…")
    pb         = prog_win['pb']
    status_lbl = prog_win['status']

    results_holder = [None]
    error_holder   = [None]

    def progress_cb(current, total):
        def _update():
            try:
                pb['value'] = int(current / total * 100)
                status_lbl.config(text=f"Day {current} of {total}")
            except Exception:
                pass
        try:
            app.root.after(0, _update)
        except Exception:
            pass

    def worker():
        try:
            secret_hex = record.secondary_shared_secret_hex or record.shared_secret_hex
            pub_key    = bytes.fromhex(record.public_key_hex)
            sks0       = bytes.fromhex(secret_hex)
            pairing    = record.pairing_date
            d0         = (bytes.fromhex(record.private_scalar_hex)
                          if record.private_scalar_hex else None)
            gen        = KeyScheduleGenerator(pub_key, sks0, pairing, d0=d0)
            results_holder[0] = gen.generate(start_dt, end_dt,
                                             progress_callback=progress_cb)
        except Exception as exc:
            error_holder[0] = exc

    t = threading.Thread(target=worker, daemon=True)
    t.start()

    def check():
        if t.is_alive():
            app.root.after(100, check)
        else:
            try:
                prog_win['win'].destroy()
            except Exception:
                pass
            if error_holder[0] is not None:
                messagebox.showerror("Error",
                    f"Key schedule generation failed:\n{error_holder[0]}")
                _log(app, f"  ✗ Key schedule error: {error_holder[0]}", "error")
            elif results_holder[0] is not None:
                _show_separated_results(app, record, results_holder[0])

    app.root.after(100, check)


# ---------------------------------------------------------------------------
# Nearby key generation — background thread + progress window
# ---------------------------------------------------------------------------

def _run_nearby_generation(app, record, num_steps: int) -> None:
    """Generate nearby-state (Pi) keys in a background thread."""
    from src.key_schedule_generator import NearbyKeyScheduleGenerator

    prog_win   = _make_progress_window(app, "Generating Nearby Key Schedule…",
                                       "Computing primary advertisement keys…")
    pb         = prog_win['pb']
    status_lbl = prog_win['status']

    results_holder = [None]
    error_holder   = [None]

    def progress_cb(current, total):
        def _update():
            try:
                pb['value'] = int(current / total * 100)
                status_lbl.config(text=f"Step {current} of {total}")
            except Exception:
                pass
        try:
            app.root.after(0, _update)
        except Exception:
            pass

    def worker():
        try:
            pub_key = bytes.fromhex(record.public_key_hex)
            skn0    = bytes.fromhex(record.shared_secret_hex)
            pairing = record.pairing_date
            d0      = (bytes.fromhex(record.private_scalar_hex)
                       if record.private_scalar_hex else None)
            gen     = NearbyKeyScheduleGenerator(pub_key, skn0, pairing, d0=d0)
            results_holder[0] = gen.generate(num_steps=num_steps,
                                             progress_callback=progress_cb)
        except Exception as exc:
            error_holder[0] = exc

    t = threading.Thread(target=worker, daemon=True)
    t.start()

    def check():
        if t.is_alive():
            app.root.after(100, check)
        else:
            try:
                prog_win['win'].destroy()
            except Exception:
                pass
            if error_holder[0] is not None:
                messagebox.showerror("Error",
                    f"Nearby key schedule generation failed:\n{error_holder[0]}")
                _log(app, f"  ✗ Nearby key schedule error: {error_holder[0]}", "error")
            elif results_holder[0] is not None:
                _show_nearby_results(app, record, results_holder[0])

    app.root.after(100, check)


# ---------------------------------------------------------------------------
# Results windows — delegate to the existing GUI modules
# ---------------------------------------------------------------------------
# We import the private _show_results helpers from the existing modules rather
# than duplicating hundreds of lines of results-window code.

def _show_separated_results(app, record, entries: list) -> None:
    from src.key_schedule_gui import _show_results
    _show_results(app, record, entries)


def _show_nearby_results(app, record, entries: list) -> None:
    from src.nearby_key_schedule_gui import _show_results
    _show_results(app, record, entries)


# ---------------------------------------------------------------------------
# Progress window helper
# ---------------------------------------------------------------------------

def _make_progress_window(app, title: str, label: str) -> dict:
    """Create and return a progress window with a progressbar and status label."""
    win = tk.Toplevel(app.root)
    win.title(title)
    win.geometry("400x130")
    win.resizable(False, False)
    win.transient(app.root)

    tk.Label(win, text=label, font=('Helvetica', 11)).pack(pady=(18, 8))
    pb = ttk.Progressbar(win, length=340, mode='determinate')
    pb.pack(padx=30)
    status_lbl = tk.Label(win, text="Starting…", font=('Helvetica', 9))
    status_lbl.pack(pady=6)

    return {'win': win, 'pb': pb, 'status': status_lbl}


# ---------------------------------------------------------------------------
# Logging helper
# ---------------------------------------------------------------------------

def _log(app, message: str, tag: str = "") -> None:
    try:
        app._log(message, tag)
    except Exception:
        print(message)
