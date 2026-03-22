"""
nearby_key_schedule_gui.py
==========================
GUI integration for the FindMy primary (nearby-state) key schedule generator.

Provides show_nearby_key_schedule_dialog() which is called from
searchpartyd_gui.py after OwnedBeacon records have been parsed.  The dialog
lets the examiner pick a beacon and a number of 15-minute steps, then
generates and displays the primary key (Pi) schedule — the MAC addresses the
beacon broadcasts when it is near its owner device.

This mirrors key_schedule_gui.py (the separated-state schedule) with these
key differences:
  • Uses sharedSecret  (SKN0) as the seed instead of secondarySharedSecret
  • Keys rotate every 15 minutes instead of every 24 hours
  • The user sets a number of days to generate (not a calendar date range)
  • The "Compare vs Observations" search matches BT MAC addresses, not
    full 28-byte advertisementData blobs (nearby-mode advertisements are
    short — just the 6-byte MAC)
  • All date/time labels are prominently marked as ESTIMATED

IMPORTANT for beginners
-----------------------
This file never does any cryptography itself.  All the maths live in
key_schedule_generator.py (NearbyKeyScheduleGenerator class).  This file
only creates windows, collects user input, kicks off background threads,
and displays results.
"""

import csv as _csv
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime, timedelta
from typing import List


# ---------------------------------------------------------------------------
# Public entry point — called from searchpartyd_gui.py
# ---------------------------------------------------------------------------

def show_nearby_key_schedule_dialog(app, owned_records: list) -> None:
    """
    Open the nearby key schedule configuration dialog.

    Parameters
    ----------
    app           : SearchpartydGUI instance (provides self.root and self._log)
    owned_records : list of OwnedBeaconRecord objects that have
                    shared_secret_hex, public_key_hex, and pairing_date
                    populated (checked before calling this function)
    """
    _open_config_dialog(app, owned_records)


# ---------------------------------------------------------------------------
# Configuration dialog
# ---------------------------------------------------------------------------

def _open_config_dialog(app, owned_records: list) -> None:
    """Show the beacon-selection and step-count dialog."""
    dlg = tk.Toplevel(app.root)
    dlg.title("Generate Nearby Key Schedule — Lost Apples")
    dlg.geometry("560x480")
    dlg.resizable(False, False)
    dlg.transient(app.root)
    dlg.grab_set()

    # Centre on parent window
    dlg.update_idletasks()
    px = app.root.winfo_rootx() + (app.root.winfo_width()  - 560) // 2
    py = app.root.winfo_rooty() + (app.root.winfo_height() - 480) // 2
    dlg.geometry(f'+{px}+{py}')

    # ---- Header bar --------------------------------------------------------
    hdr = tk.Frame(dlg, bg='#1a4f3a', pady=10)   # dark green — distinct from separated (dark blue)
    hdr.pack(fill='x')
    tk.Label(hdr, text="FindMy Nearby / Connected Mode Schedule Generator",
             bg='#1a4f3a', fg='white',
             font=('Helvetica', 13, 'bold')).pack()
    tk.Label(hdr,
             text="Reconstruct 15-minute BLE advertisement keys & MAC addresses "
                  "for a beacon in nearby/connected state",
             bg='#1a4f3a', fg='#a0c8b0',
             font=('Helvetica', 9)).pack()

    # ---- Body area ---------------------------------------------------------
    body = tk.Frame(dlg, padx=20, pady=15)
    body.pack(fill='both', expand=True)
    body.columnconfigure(1, weight=1)

    # Beacon selector — build readable labels from OwnedBeaconRecord fields
    tk.Label(body, text="Beacon:", font=('Helvetica', 10, 'bold'),
             anchor='w').grid(row=0, column=0, sticky='w', pady=6)

    beacon_labels = []
    for rec in owned_records:
        name  = rec.custom_name or ''
        emoji = rec.emoji or ''
        uid   = str(rec.identifier or 'Unknown')
        short = uid[:8] + '…'
        if name and emoji:
            label = f"{emoji} {name}  [{short}]"
        elif name:
            label = f"{name}  [{short}]"
        elif rec.model:
            label = f"{rec.model}  [{short}]"
        else:
            label = f"[{short}]"
        beacon_labels.append(label)

    beacon_var = tk.StringVar(value=beacon_labels[0])
    beacon_menu = ttk.Combobox(body, textvariable=beacon_var,
                                values=beacon_labels, state='readonly', width=46)
    beacon_menu.grid(row=0, column=1, sticky='ew', pady=6, padx=(8, 0))

    # Days to generate (each day = 96 steps × 15 min)
    tk.Label(body, text="Days to generate:", font=('Helvetica', 10, 'bold'),
             anchor='w').grid(row=1, column=0, sticky='w', pady=6)

    days_var = tk.StringVar(value='7')
    days_entry = tk.Entry(body, textvariable=days_var, width=8,
                          font=('Courier', 10))
    days_entry.grid(row=1, column=1, sticky='w', pady=6, padx=(8, 0))

    tk.Label(body,
             text="Each day = 96 keys (one per 15 minutes).  "
                  "7 days = 672 keys, 30 days = 2,880 keys.",
             font=('Helvetica', 8)
             ).grid(row=2, column=0, columnspan=2, sticky='w', pady=(0, 4))

    # Pairing date display (read-only — the anchor for time estimates)
    tk.Label(body, text="Pairing date (anchor):", font=('Helvetica', 10, 'bold'),
             anchor='w').grid(row=3, column=0, sticky='w', pady=4)

    pairing_lbl = tk.Label(body, text='—', font=('Courier', 9), anchor='w')
    pairing_lbl.grid(row=3, column=1, sticky='w', pady=4, padx=(8, 0))

    def update_pairing_label(event=None):
        """Refresh the pairing date label when a different beacon is selected."""
        idx = beacon_labels.index(beacon_var.get()) if beacon_var.get() in beacon_labels else 0
        rec = owned_records[idx]
        if rec.pairing_date:
            pd_str = rec.pairing_date.strftime('%Y-%m-%d %H:%M')
            pairing_lbl.config(text=f"{pd_str}  (step 1 anchor — ESTIMATED)")
        else:
            pairing_lbl.config(text='Not available')

    beacon_menu.bind('<<ComboboxSelected>>', update_pairing_label)
    update_pairing_label()   # populate immediately for the first beacon

    # Info / help box
    info = tk.Text(body, height=7, width=58, wrap='word',
                   relief='flat', font=('Helvetica', 9),
                   padx=6, pady=6)
    info.grid(row=4, column=0, columnspan=2, sticky='ew', pady=(10, 0))
    info.insert('1.0',
        "Generate Schedule — builds a table of 15-minute BLE MACs starting "
        "from the pairing date.  Useful for identifying which MAC a beacon "
        "was using when it was near its owner during a specific window.\n\n"
        "Compare vs Observations — loads a Lost Apples Observations.db CSV "
        "export and searches every derived Pi MAC address for matches in the "
        "MAC_Address column.  The full key chain is searched automatically "
        "(no date filter needed).\n\n"
        "⚠ All dates and times are ESTIMATED.  iOS periodically rotates "
        "sharedSecret; the pairing date anchor may be inaccurate."
    )
    info.config(state='disabled')

    # ---- Button row --------------------------------------------------------
    btn_row = tk.Frame(dlg, pady=12)
    btn_row.pack()

    def _get_selected_record():
        """Helper: return the OwnedBeaconRecord matching the current dropdown."""
        idx = beacon_labels.index(beacon_var.get()) if beacon_var.get() in beacon_labels else 0
        return owned_records[idx]

    def _validate_days() -> int:
        """Parse and validate the days field.  Returns int or raises ValueError."""
        raw = days_var.get().strip()
        try:
            days = int(raw)
        except ValueError:
            raise ValueError("Days must be a whole number (e.g. 7).")
        if days < 1 or days > 3650:
            raise ValueError("Days must be between 1 and 3,650 (10 years).")
        return days

    def on_generate():
        record = _get_selected_record()

        try:
            days = _validate_days()
        except ValueError as e:
            messagebox.showerror("Invalid input", str(e), parent=dlg)
            return

        if not record.pairing_date:
            messagebox.showerror("Missing pairing date",
                                 "This beacon record does not have a pairing date,\n"
                                 "which is required to anchor the key schedule.",
                                 parent=dlg)
            return

        if not record.public_key_hex:
            messagebox.showerror("Missing public key",
                                 "This beacon does not have a publicKey,\n"
                                 "which is required for derivation.",
                                 parent=dlg)
            return

        if not record.shared_secret_hex:
            messagebox.showerror("Missing sharedSecret",
                                 "This beacon does not have a sharedSecret (SKN0),\n"
                                 "which seeds the nearby key schedule.",
                                 parent=dlg)
            return

        # num_steps: 96 steps per day (96 × 15 min = 24 h)
        num_steps = days * 96
        dlg.destroy()
        _run_generation(app, record, num_steps)

    def on_compare():
        record = _get_selected_record()

        if not record.public_key_hex:
            messagebox.showerror("Missing public key",
                                 "This beacon does not have a publicKey.",
                                 parent=dlg)
            return
        if not record.shared_secret_hex:
            messagebox.showerror("Missing sharedSecret",
                                 "This beacon does not have a sharedSecret (SKN0).",
                                 parent=dlg)
            return
        if not record.pairing_date:
            messagebox.showerror("Missing pairing date",
                                 "This beacon record does not have a pairing date.",
                                 parent=dlg)
            return

        csv_path = filedialog.askopenfilename(
            parent=dlg,
            title="Select Observations.db CSV export",
            filetypes=[('CSV files', '*.csv'), ('All files', '*.*')],
        )
        if not csv_path:
            return   # user cancelled the file picker

        dlg.destroy()
        _run_comparison(app, record, csv_path)

    tk.Button(btn_row, text="Generate Schedule", command=on_generate,
              font=('Helvetica', 10), padx=12, pady=4,
              cursor='hand2').pack(side='left', padx=6)

    tk.Button(btn_row, text="Compare vs Observations", command=on_compare,
              font=('Helvetica', 10), padx=12, pady=4,
              cursor='hand2').pack(side='left', padx=6)

    tk.Button(btn_row, text="Cancel", command=dlg.destroy,
              font=('Helvetica', 10), padx=12, pady=4).pack(side='left', padx=6)


# ---------------------------------------------------------------------------
# Background computation — Generate Schedule
# ---------------------------------------------------------------------------

def _run_generation(app, record, num_steps: int) -> None:
    """
    Launch primary key generation in a background thread.

    We use a background thread so the GUI stays responsive while the
    cryptographic computation runs.  tkinter is NOT thread-safe, so
    this function never calls any tkinter code directly inside the
    worker thread — only through app.root.after() callbacks.
    """
    from src.key_schedule_generator import NearbyKeyScheduleGenerator

    # Progress window
    prog_win = tk.Toplevel(app.root)
    prog_win.title("Generating Nearby Key Schedule…")
    prog_win.geometry("380x130")
    prog_win.resizable(False, False)
    prog_win.transient(app.root)

    tk.Label(prog_win, text="Computing primary advertisement keys…",
             font=('Helvetica', 11)).pack(pady=(18, 8))
    pb = ttk.Progressbar(prog_win, length=320, mode='determinate')
    pb.pack(padx=30)
    status_lbl = tk.Label(prog_win, text="Starting…", font=('Helvetica', 9))
    status_lbl.pack(pady=6)

    results_holder = [None]
    error_holder   = [None]

    def progress_cb(current, total):
        # Schedule the UI update on the main thread — NEVER update tkinter
        # widgets directly from a background thread.
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

            # Pass d0 (the 28-byte private scalar) so the generator can use
            # the fast OpenSSL-backed derivation path.
            d0 = bytes.fromhex(record.private_scalar_hex) if record.private_scalar_hex else None

            gen = NearbyKeyScheduleGenerator(pub_key, skn0, pairing, d0=d0)
            entries = gen.generate(num_steps=num_steps,
                                   progress_callback=progress_cb)
            results_holder[0] = entries
        except Exception as exc:
            error_holder[0] = exc
        # Do NOT touch tkinter here — let check() handle it on the main thread.

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
                    "Error",
                    f"Nearby key schedule generation failed:\n{error_holder[0]}"
                )
                _log(app, f"  ✗ Nearby key schedule error: {error_holder[0]}", "error")
            elif results_holder[0] is not None:
                _show_results(app, record, results_holder[0])

    app.root.after(100, check)


# ---------------------------------------------------------------------------
# Background computation — Compare vs Observations
# ---------------------------------------------------------------------------

def _run_comparison(app, record, csv_path: str) -> None:
    """
    Parse the Observations.db CSV then search all derived Pi MACs for matches.

    Unlike the separated-mode comparison (which looks at 28-byte
    advertisementData), this search matches the derived 6-byte BLE MAC
    address against the MAC_Address column in the CSV.  This is appropriate
    for nearby/connected-state observations, where the advertisement is short.
    """
    from src.key_schedule_generator import NearbyKeyScheduleGenerator

    # ---- Parse the CSV ----------------------------------------------------
    # We collect every row's MAC_Address + Seen_Time, regardless of advertisement
    # length, because nearby-mode rows may not have a full 28-byte adv payload.
    mac_targets = []    # list of (mac_str, seen_time)
    try:
        with open(csv_path, 'r', encoding='utf-8', errors='replace') as f:
            lines = [l for l in f if not l.startswith('#')]
        reader = _csv.DictReader(lines)
        for row in reader:
            mac = row.get('MAC_Address', '').strip()
            if mac:
                mac_targets.append((
                    mac,
                    row.get('Seen_Time', ''),
                ))
    except Exception as exc:
        messagebox.showerror("CSV Error",
                             f"Could not read Observations CSV:\n{exc}")
        return

    if not mac_targets:
        messagebox.showwarning(
            "No MAC Addresses Found",
            "The selected CSV contains no MAC_Address values.\n"
            "Please select a valid Observations.db CSV export."
        )
        return

    # Remove duplicate MACs (keep first occurrence's seen_time for display)
    seen_macs: set = set()
    unique_targets = []
    for mac, seen_time in mac_targets:
        norm = mac.upper().replace(':', '').replace('-', '').replace(' ', '')
        if norm not in seen_macs:
            seen_macs.add(norm)
            unique_targets.append((mac, seen_time))

    _log(app, f"  Comparing {len(unique_targets)} unique MAC addresses "
              f"from {csv_path}")

    # Calculate how many 15-minute key steps to derive.
    # 900 seconds = 15 minutes. We derive only from the pairing date up to
    # today, plus a 1-day buffer (96 steps) to handle edge cases.
    # If pairing_date is unavailable we fall back to the old maximum.
    _today = datetime.now()
    _pairing = record.pairing_date
    if _pairing and _pairing < _today:
        _seconds_since_pairing = (_today - _pairing).total_seconds()
        steps_to_search = int(_seconds_since_pairing / 900) + 96   # +1 day buffer
    else:
        steps_to_search = 10000   # fallback if pairing date is unavailable
    steps_to_search = max(1, steps_to_search)
    _log(app, f"  Key range: {steps_to_search} step(s) "
              f"(pairing date \u2192 today + 1-day buffer)")

    # ---- Progress window --------------------------------------------------
    prog_win = tk.Toplevel(app.root)
    prog_win.title("Comparing Nearby Keys…")
    prog_win.geometry("400x130")
    prog_win.resizable(False, False)
    prog_win.transient(app.root)

    tk.Label(prog_win,
             text="Searching primary key chain for MAC address matches…",
             font=('Helvetica', 11)).pack(pady=(18, 8))
    pb = ttk.Progressbar(prog_win, length=340, mode='determinate')
    pb.pack(padx=30)
    status_lbl = tk.Label(prog_win, text="Starting…", font=('Helvetica', 9))
    status_lbl.pack(pady=6)

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

            # Pass d0 so the generator can use the fast OpenSSL derivation path.
            d0 = bytes.fromhex(record.private_scalar_hex) if record.private_scalar_hex else None

            gen = NearbyKeyScheduleGenerator(pub_key, skn0, pairing, d0=d0)
            matches = gen.search_observations(
                unique_targets,
                max_steps=steps_to_search,
                progress_callback=progress_cb,
            )
            results_holder[0] = matches
        except Exception as exc:
            error_holder[0] = exc

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
                    "Error",
                    f"Comparison failed:\n{error_holder[0]}"
                )
                _log(app, f"  ✗ Nearby comparison error: {error_holder[0]}", "error")
            elif results_holder[0] is not None:
                _show_comparison_results(app, record, results_holder[0], csv_path)

    app.root.after(100, check)


# ---------------------------------------------------------------------------
# Results window — Generate Schedule
# ---------------------------------------------------------------------------

def _show_results(app, record, entries: list) -> None:
    """Display the generated nearby key schedule in a scrollable results window."""
    beacon_id   = str(record.identifier or 'Unknown')
    beacon_name = record.custom_name or ''
    emoji       = record.emoji or ''
    model       = record.model or ''

    # Build a readable title string for window title and header
    if beacon_name and emoji:
        title_str = f"{emoji} {beacon_name}  [{beacon_id[:8]}…]"
    elif beacon_name:
        title_str = f"{beacon_name}  [{beacon_id[:8]}…]"
    elif model:
        title_str = f"{model}  [{beacon_id[:8]}…]"
    else:
        title_str = f"[{beacon_id}]"

    _log(app,
         f"  ✓ Nearby key schedule: {len(entries)} steps for {title_str}",
         "success")

    win = tk.Toplevel(app.root)
    win.title(f"Nearby Key Schedule — {title_str}")
    win.geometry("900x580")
    win.resizable(True, True)
    win.transient(app.root)

    # ---- Header bar --------------------------------------------------------
    hdr = tk.Frame(win, bg='#1a4f3a', pady=8)
    hdr.pack(fill='x')
    tk.Label(hdr,
             text=f"📡  Nearby Key Schedule  |  {title_str}",
             bg='#1a4f3a', fg='white',
             font=('Helvetica', 12, 'bold')).pack(side='left', padx=12)
    tk.Label(hdr,
             text=f"{len(entries)} steps  •  15-min intervals",
             bg='#1a4f3a', fg='#a0c8b0',
             font=('Helvetica', 10)).pack(side='right', padx=12)

    # ---- Table (Treeview) -------------------------------------------------
    # Columns: step index, estimated datetime, BLE MAC, Pi hex
    cols = ('step', 'est_datetime', 'ble_addr', 'pi_hex')
    col_cfg = {
        'step':         ('Step i',                  65,  'center'),
        'est_datetime': ('Est. Date/Time *',        160,  'center'),
        'ble_addr':     ('BLE Address',             165,  'center'),
        'pi_hex':       ('Pi Hex (28 bytes)',        400,  'w'),
    }

    tree_frame = tk.Frame(win)
    tree_frame.pack(fill='both', expand=True, padx=8, pady=6)

    vsb = ttk.Scrollbar(tree_frame, orient='vertical')
    hsb = ttk.Scrollbar(tree_frame, orient='horizontal')
    tree = ttk.Treeview(tree_frame, columns=cols, show='headings',
                         yscrollcommand=vsb.set, xscrollcommand=hsb.set,
                         height=22)
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

    # Populate rows
    for i, e in enumerate(entries):
        tag = 'even' if i % 2 == 0 else 'odd'
        tree.insert('', 'end', values=(
            e.step_index,
            e.datetime_str,
            e.ble_address_str,
            e.p_i_bytes.hex(),
        ), tags=(tag,))

    # ---- Bottom bar --------------------------------------------------------
    bar = tk.Frame(win, pady=8)
    bar.pack(fill='x', padx=8)

    # Footnote explaining the "estimated" caveat
    tk.Label(
        bar,
        text=(
            "* Est. Date/Time = pairingDate + (step × 15 min).  "
            "iOS may rotate sharedSecret after pairing, shifting the anchor — "
            "treat all dates as approximate.  "
            "Use 'Compare vs Observations' for forensically reliable timestamps."
        ),
        font=('Helvetica', 8), fg='#555555', wraplength=780, justify='left'
    ).pack(side='left')

    def export_csv():
        path = filedialog.asksaveasfilename(
            parent=win,
            defaultextension='.csv',
            filetypes=[('CSV files', '*.csv'), ('All files', '*.*')],
            initialfile=f'nearby_schedule_{beacon_id[:8]}.csv',
            title='Save Nearby Key Schedule CSV',
        )
        if not path:
            return
        from src.key_schedule_generator import NearbyKeyScheduleGenerator
        NearbyKeyScheduleGenerator.export_csv(entries, beacon_id, path)
        messagebox.showinfo("Exported",
                            f"Nearby key schedule saved to:\n{path}",
                            parent=win)
        _log(app, f"  ✓ Nearby key schedule exported: {path}", "success")

    tk.Button(bar, text="📄  Export CSV", command=export_csv,
              font=('Helvetica', 10, 'bold'),
              padx=10, pady=3, cursor='hand2').pack(side='right')


# ---------------------------------------------------------------------------
# Results window — Compare vs Observations
# ---------------------------------------------------------------------------

def _show_comparison_results(app, record, matches: list, csv_path: str) -> None:
    """Display confirmed Pi MAC matches against Observations.db rows."""
    beacon_id   = str(record.identifier or 'Unknown')
    beacon_name = record.custom_name or ''
    emoji       = record.emoji or ''
    model       = record.model or ''

    if beacon_name and emoji:
        title_str = f"{emoji} {beacon_name}  [{beacon_id[:8]}…]"
    elif beacon_name:
        title_str = f"{beacon_name}  [{beacon_id[:8]}…]"
    elif model:
        title_str = f"{model}  [{beacon_id[:8]}…]"
    else:
        title_str = f"[{beacon_id}]"

    if matches:
        _log(app,
             f"  ✓ {len(matches)} nearby observation match(es) found for {title_str}",
             "success")
    else:
        _log(app,
             f"  ⚠ No nearby observation matches found for {title_str} in {csv_path}",
             "warning")

    win = tk.Toplevel(app.root)
    win.title(f"Nearby Observation Matches — {title_str}")
    win.geometry("1060x520")
    win.resizable(True, True)
    win.transient(app.root)

    # ---- Header bar --------------------------------------------------------
    hdr = tk.Frame(win, bg='#1a4f3a', pady=8)
    hdr.pack(fill='x')
    tk.Label(hdr,
             text=f"🔍  Nearby Observations.db Matches  |  {title_str}",
             bg='#1a4f3a', fg='white',
             font=('Helvetica', 12, 'bold')).pack(side='left', padx=12)
    count_text = f"{len(matches)} match(es)" if matches else "No matches"
    tk.Label(hdr, text=count_text,
             bg='#1a4f3a', fg='#a0c8b0',
             font=('Helvetica', 10)).pack(side='right', padx=12)

    # ---- No-match message -------------------------------------------------
    if not matches:
        msg = (
            "No Pi keys derived from this beacon's sharedSecret\n"
            "matched any MAC_Address in the selected Observations.db CSV.\n\n"
            "Possible reasons:\n"
            "  • This beacon was not near a scanning device during the time window\n"
            "    covered by the Observations.db.\n"
            "  • The beacon was only seen in separated mode (away from owner).\n"
            "    Try the Separated Key Schedule feature instead.\n"
            "  • iOS has rotated sharedSecret since pairing, making the Pi\n"
            "    derivation start from a different point than this record shows.\n"
            "  • The Observations.db is from a different device."
        )
        tk.Label(win, text=msg, font=('Helvetica', 10),
                 justify='left', padx=20, pady=20).pack(anchor='w')
        return

    # ---- Table (Treeview) -------------------------------------------------
    cols = ('step', 'est_datetime', 'ble_derived', 'observed_mac',
            'observed_time', 'pi_hex')
    col_cfg = {
        'step':          ('Step i',           65,  'center'),
        'est_datetime':  ('Est. Date/Time *', 150,  'center'),
        'ble_derived':   ('Derived BLE',      160,  'center'),
        'observed_mac':  ('Observed MAC',     160,  'center'),
        'observed_time': ('Seen Time',        185,  'center'),
        'pi_hex':        ('Pi Hex (28 bytes)', 360,  'w'),
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

    for i, m in enumerate(matches):
        tag = 'even' if i % 2 == 0 else 'odd'
        tree.insert('', 'end', values=(
            m.step_index,
            m.estimated_datetime_str,
            m.ble_address_str,
            m.observed_mac,
            m.observed_time,
            m.p_i_bytes.hex(),
        ), tags=(tag,))

    # ---- Bottom bar --------------------------------------------------------
    bar = tk.Frame(win, pady=6)
    bar.pack(fill='x', padx=8)

    tk.Label(
        bar,
        text=(
            "* Est. Date/Time = pairingDate + (step × 15 min).  "
            "iOS may rotate sharedSecret after pairing — dates are approximate.  "
            "The observed Seen_Time from Observations.db is the reliable timestamp."
        ),
        font=('Helvetica', 8), fg='#555555'
    ).pack(side='left')

    def export_csv():
        path = filedialog.asksaveasfilename(
            parent=win,
            defaultextension='.csv',
            filetypes=[('CSV files', '*.csv'), ('All files', '*.*')],
            initialfile=f'nearby_obs_matches_{beacon_id[:8]}.csv',
            title='Save Nearby Observation Matches CSV',
        )
        if not path:
            return
        from src.key_schedule_generator import NearbyKeyScheduleGenerator
        NearbyKeyScheduleGenerator.export_matches_csv(matches, beacon_id, path)
        messagebox.showinfo("Exported",
                            f"Matches saved to:\n{path}",
                            parent=win)
        _log(app, f"  ✓ Nearby observation matches exported: {path}", "success")

    tk.Button(bar, text="📄  Export CSV", command=export_csv,
              font=('Helvetica', 10, 'bold'),
              padx=10, pady=3, cursor='hand2').pack(side='right')


# ---------------------------------------------------------------------------
# Logging helper
# ---------------------------------------------------------------------------

def _log(app, message: str, tag: str = "") -> None:
    """Write to the main GUI log, falling back to print() if unavailable."""
    try:
        app._log(message, tag)
    except Exception:
        print(message)
