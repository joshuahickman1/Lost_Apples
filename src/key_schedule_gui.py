"""
key_schedule_gui.py
===================
GUI integration for the FindMy secondary key schedule generator.

Provides show_key_schedule_dialog() which is called from searchpartyd_gui.py
after OwnedBeacon records have been parsed.  The dialog lets the examiner
pick a beacon and date range, then generates and displays the daily BLE
advertisement key schedule, including the randomized MAC addresses, for that beacon in separated state.

This is intentionally on-demand — the button that opens it is enabled only
after parsing, following the same pattern as the Query Observations button.
"""

import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime, timedelta
from typing import List


# ---------------------------------------------------------------------------
# Public entry point — called from searchpartyd_gui.py
# ---------------------------------------------------------------------------

def show_key_schedule_dialog(app, owned_records: list) -> None:
    """
    Open the key schedule configuration dialog.

    Parameters
    ----------
    app           : SearchpartydGUI instance (used for self.root and self._log)
    owned_records : list of OwnedBeaconRecord objects that have
                    secondary_shared_secret_hex populated
    """
    _open_config_dialog(app, owned_records)


# ---------------------------------------------------------------------------
# Configuration dialog
# ---------------------------------------------------------------------------

def _open_config_dialog(app, owned_records: list) -> None:
    """Show the beacon/date-range selection dialog."""
    dlg = tk.Toplevel(app.root)
    dlg.title("Generate Key Schedule — Lost Apples")
    dlg.geometry("540x460")
    dlg.resizable(False, False)
    dlg.transient(app.root)
    dlg.grab_set()

    # Centre on parent
    dlg.update_idletasks()
    px = app.root.winfo_rootx() + (app.root.winfo_width()  - 540) // 2
    py = app.root.winfo_rooty() + (app.root.winfo_height() - 430) // 2
    dlg.geometry(f'+{px}+{py}')

    # ---- Header ----
    hdr = tk.Frame(dlg, bg='#1e3a5f', pady=10)
    hdr.pack(fill='x')
    tk.Label(hdr, text="FindMy Separated Mode Schedule Generator",
             bg='#1e3a5f', fg='white',
             font=('Helvetica', 13, 'bold')).pack()
    tk.Label(hdr,
             text="Reconstruct daily BLE advertisement keys & Randomized MAC addresses for a beacon in a separated state",
             bg='#1e3a5f', fg='#aac4e0',
             font=('Helvetica', 9)).pack()

    # ---- Body ----
    body = tk.Frame(dlg, padx=20, pady=15)
    body.pack(fill='both', expand=True)
    body.columnconfigure(1, weight=1)

    # Beacon selector — build labels from OwnedBeaconRecord fields
    tk.Label(body, text="Beacon:", font=('Helvetica', 10, 'bold'),
             anchor='w').grid(row=0, column=0, sticky='w', pady=6)

    beacon_labels = []
    for rec in owned_records:
        name  = rec.custom_name or ''
        emoji = rec.emoji or ''
        uid   = str(rec.identifier or 'Unknown')
        short = uid[:8] + '…'
        # Warn when falling back to primary sharedSecret (e.g. iPhone records)
        key_tag = '' if rec.secondary_shared_secret_hex else ' ⚠ primary key'
        if name and emoji:
            label = f"{emoji} {name}  [{short}]{key_tag}"
        elif name:
            label = f"{name}  [{short}]{key_tag}"
        elif rec.model:
            label = f"{rec.model}  [{short}]{key_tag}"
        else:
            label = f"[{short}]{key_tag}"
        beacon_labels.append(label)

    beacon_var = tk.StringVar(value=beacon_labels[0])
    beacon_menu = ttk.Combobox(body, textvariable=beacon_var,
                                values=beacon_labels, state='readonly', width=46)
    beacon_menu.grid(row=0, column=1, sticky='ew', pady=6, padx=(8, 0))

    # Date fields
    tk.Label(body, text="Start date:", font=('Helvetica', 10, 'bold'),
             anchor='w').grid(row=1, column=0, sticky='w', pady=6)
    start_var = tk.StringVar(
        value=(datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d'))
    tk.Entry(body, textvariable=start_var, width=18,
             font=('Courier', 10)).grid(row=1, column=1, sticky='w',
                                        pady=6, padx=(8, 0))

    tk.Label(body, text="End date:", font=('Helvetica', 10, 'bold'),
             anchor='w').grid(row=2, column=0, sticky='w', pady=6)
    end_var = tk.StringVar(value=datetime.now().strftime('%Y-%m-%d'))
    tk.Entry(body, textvariable=end_var, width=18,
             font=('Courier', 10)).grid(row=2, column=1, sticky='w',
                                        pady=6, padx=(8, 0))

    tk.Label(body,
             text="Dates in YYYY-MM-DD format.  Keys activate at 4:00 AM local each day.",
             font=('Helvetica', 8)
             ).grid(row=3, column=0, columnspan=2, sticky='w', pady=(0, 12))

    # Info box
    info = tk.Text(body, height=6, width=56, wrap='word',
                   relief='flat', font=('Helvetica', 9),
                   padx=6, pady=6)
    info.grid(row=4, column=0, columnspan=2, sticky='ew')
    info.insert('1.0',
        "Generate Schedule — produces a table of daily BLE addresses and keys "
        "for a chosen date range.  Useful for Wireshark filters and BLE scanners.\n\n"
        "Compare vs Observations — loads a Lost Apples Observations.db CSV export "
        "and searches every derived key for exact byte matches against the "
        "advertisementData column.  No date range required; the full key chain "
        "is searched automatically.\n\n"
        "Note: 'Est. Date' in comparison results is approximate — iOS may rotate "
        "the secondary secret after pairing, offsetting the date labels."
    )
    info.config(state='disabled')

    # ---- Buttons ----
    btn_row = tk.Frame(dlg, pady=12)
    btn_row.pack()

    def on_generate():
        idx = beacon_labels.index(beacon_var.get()) if beacon_var.get() in beacon_labels else 0
        record = owned_records[idx]

        try:
            start_dt = datetime.strptime(start_var.get().strip(), '%Y-%m-%d')
            end_dt   = datetime.strptime(end_var.get().strip(), '%Y-%m-%d')
        except ValueError:
            messagebox.showerror("Invalid date",
                                 "Please enter dates in YYYY-MM-DD format.",
                                 parent=dlg)
            return

        if start_dt > end_dt:
            messagebox.showerror("Invalid range",
                                 "Start date must be on or before end date.",
                                 parent=dlg)
            return

        # Check pairing date is available so we can anchor the key schedule
        if not record.pairing_date:
            messagebox.showerror("Missing pairing date",
                                 "This beacon record does not have a pairing date,\n"
                                 "which is required to anchor the key schedule.",
                                 parent=dlg)
            return

        # Check that the required cryptographic fields are present
        if not record.public_key_hex:
            messagebox.showerror("Missing public key",
                                 "This beacon does not have a publicKey,\n"
                                 "which is required to generate the key schedule.",
                                 parent=dlg)
            return

        if not record.secondary_shared_secret_hex and not record.shared_secret_hex:
            messagebox.showerror("Missing shared secret",
                                 "This beacon has neither a secondarySharedSecret nor a\n"
                                 "sharedSecret — key schedule derivation is not possible.",
                                 parent=dlg)
            return

        if not record.secondary_shared_secret_hex:
            if not messagebox.askokcancel(
                "Using Primary Shared Secret",
                "This beacon has no secondarySharedSecret.\n\n"
                "The key schedule will be derived from the primary sharedSecret instead.\n"
                "This is typical for iPhone records, which do not use the accessory\n"
                "secondary key scheme.  Results may not match AirTag-style observations.\n\n"
                "Continue?",
                parent=dlg,
            ):
                return

        dlg.destroy()
        _run_generation(app, record, start_dt, end_dt)

    def on_compare():
        idx = beacon_labels.index(beacon_var.get()) if beacon_var.get() in beacon_labels else 0
        record = owned_records[idx]

        if not record.public_key_hex:
            messagebox.showerror("Missing public key",
                                 "This beacon does not have a publicKey.",
                                 parent=dlg)
            return
        if not record.secondary_shared_secret_hex and not record.shared_secret_hex:
            messagebox.showerror("Missing shared secret",
                                 "This beacon has neither a secondarySharedSecret nor a\n"
                                 "sharedSecret — key comparison is not possible.",
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
            return

        dlg.destroy()
        _run_comparison(app, record, csv_path)

    tk.Button(btn_row, text="Generate Schedule", command=on_generate,
              font=('Helvetica', 10),
              padx=12, pady=4, cursor='hand2').pack(side='left', padx=6)

    tk.Button(btn_row, text="Compare vs Observations", command=on_compare,
              font=('Helvetica', 10),
              padx=12, pady=4, cursor='hand2').pack(side='left', padx=6)

    tk.Button(btn_row, text="Cancel", command=dlg.destroy,
              font=('Helvetica', 10), padx=12, pady=4).pack(side='left', padx=6)


# ---------------------------------------------------------------------------
# Background computation + progress window
# ---------------------------------------------------------------------------

def _run_generation(app, record, start_dt: datetime, end_dt: datetime):
    """Launch key generation in a background thread with a progress window."""
    from src.key_schedule_generator import KeyScheduleGenerator

    # Progress window
    prog_win = tk.Toplevel(app.root)
    prog_win.title("Generating Key Schedule…")
    prog_win.geometry("380x130")
    prog_win.resizable(False, False)
    prog_win.transient(app.root)

    tk.Label(prog_win, text="Computing advertisement keys…",
             font=('Helvetica', 11)).pack(pady=(18, 8))
    pb = ttk.Progressbar(prog_win, length=320, mode='determinate')
    pb.pack(padx=30)
    status_lbl = tk.Label(prog_win, text="Starting…",
                          font=('Helvetica', 9))
    status_lbl.pack(pady=6)

    results_holder = [None]
    error_holder   = [None]

    def progress_cb(current, total):
        # Schedule the UI update on the main thread — tkinter is NOT thread-safe
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
            # OwnedBeaconRecord stores key material as hex strings.
            # Fall back to primary sharedSecret when secondarySharedSecret is absent
            # (typical for iPhone OwnedBeacon records).
            secret_hex = record.secondary_shared_secret_hex or record.shared_secret_hex
            pub_key = bytes.fromhex(record.public_key_hex)
            sks0    = bytes.fromhex(secret_hex)
            pairing = record.pairing_date   # already a datetime

            # Pass d0 (the 28-byte private scalar) so the generator can use
            # the fast OpenSSL-backed derivation path.
            d0 = bytes.fromhex(record.private_scalar_hex) if record.private_scalar_hex else None

            gen = KeyScheduleGenerator(pub_key, sks0, pairing, d0=d0)
            entries = gen.generate(start_dt, end_dt, progress_callback=progress_cb)
            results_holder[0] = entries
        except Exception as exc:
            error_holder[0] = exc
        # NOTE: Do NOT call any tkinter operations here — this is a background
        # thread.  The check() function running on the main thread handles
        # closing the progress window and showing results or errors.

    t = threading.Thread(target=worker, daemon=True)
    t.start()

    def check():
        if t.is_alive():
            # Reschedule on the main window — prog_win may be destroyed by the
            # time a late callback fires, so always anchor to app.root.
            app.root.after(100, check)
        else:
            # Destroy the progress window from the main thread (thread-safe)
            try:
                prog_win.destroy()
            except Exception:
                pass

            if error_holder[0] is not None:
                messagebox.showerror(
                    "Error",
                    f"Key schedule generation failed:\n{error_holder[0]}"
                )
                _log(app, f"  ✗ Key schedule error: {error_holder[0]}", "error")
            elif results_holder[0] is not None:
                _show_results(app, record, results_holder[0])

    # Schedule the first check on app.root (not prog_win) so it survives
    # regardless of what happens to the progress window.
    app.root.after(100, check)


# ---------------------------------------------------------------------------
# Observations comparison — background computation
# ---------------------------------------------------------------------------

def _run_comparison(app, record, csv_path: str) -> None:
    """Parse the Observations CSV then search all derived keys for matches."""
    import csv as _csv
    from src.key_schedule_generator import KeyScheduleGenerator

    # ---- Parse the CSV ------------------------------------------------
    targets = []   # list of (adv_hex, mac_str, seen_time)
    try:
        with open(csv_path, 'r', encoding='utf-8', errors='replace') as f:
            lines = [l for l in f if not l.startswith('#')]
        reader = _csv.DictReader(lines)
        for row in reader:
            adv = row.get('Advertised_Data', '').replace(' ', '').strip()
            if len(adv) == 56:   # 28 bytes = separated-mode advertisement
                targets.append((
                    adv,
                    row.get('MAC_Address', ''),
                    row.get('Seen_Time', ''),
                ))
    except Exception as exc:
        messagebox.showerror("CSV Error",
                             f"Could not read Observations CSV:\n{exc}")
        return

    if not targets:
        messagebox.showwarning(
            "No Separated-Mode Rows",
            "The selected CSV contains no 28-byte advertisementData rows.\n"
            "Only separated-mode observations (full 28-byte PWj) can be matched."
        )
        return

    unique_adv = len({t[0] for t in targets})
    _log(app, f"  Comparing {unique_adv} unique advertisementData values "
              f"from {csv_path}")

    # Calculate how many days of keys to derive.
    # Rather than always computing a fixed maximum (which wastes time for
    # beacons paired recently), we derive only from the pairing date up to
    # today, plus a 7-day buffer to handle any clock/timezone edge cases.
    # If pairing_date is unavailable we fall back to the old maximum.
    _today = datetime.now()
    _pairing = record.pairing_date
    if _pairing and _pairing < _today:
        days_to_search = (_today - _pairing).days + 7   # +7 day buffer
    else:
        days_to_search = 3000   # fallback if pairing date is unavailable
    days_to_search = max(1, days_to_search)
    _log(app, f"  Key range: {days_to_search} day(s) "
              f"(pairing date \u2192 today + 7-day buffer)")

    # ---- Progress window ---------------------------------------------
    prog_win = tk.Toplevel(app.root)
    prog_win.title("Comparing Keys…")
    prog_win.geometry("400x130")
    prog_win.resizable(False, False)
    prog_win.transient(app.root)

    tk.Label(prog_win, text="Searching key chain for observation matches…",
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
            # Fall back to primary sharedSecret when secondarySharedSecret is absent
            # (typical for iPhone OwnedBeacon records).
            secret_hex = record.secondary_shared_secret_hex or record.shared_secret_hex
            pub_key = bytes.fromhex(record.public_key_hex)
            sks0    = bytes.fromhex(secret_hex)
            pairing = record.pairing_date

            # Pass d0 so the generator can use the fast OpenSSL derivation path.
            d0 = bytes.fromhex(record.private_scalar_hex) if record.private_scalar_hex else None

            gen = KeyScheduleGenerator(pub_key, sks0, pairing, d0=d0)
            matches = gen.search_observations(
                targets,
                max_days=days_to_search,
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
                _log(app, f"  ✗ Comparison error: {error_holder[0]}", "error")
            elif results_holder[0] is not None:
                _show_comparison_results(app, record, results_holder[0], csv_path)

    app.root.after(100, check)


# ---------------------------------------------------------------------------
# Observations comparison — results window
# ---------------------------------------------------------------------------

def _show_comparison_results(app, record, matches: list, csv_path: str) -> None:
    """Display confirmed PWj matches against Observations.db rows."""
    beacon_id   = str(record.identifier or 'Unknown')
    beacon_name = record.custom_name or ''
    emoji       = record.emoji or ''

    if beacon_name and emoji:
        title_str = f"{emoji} {beacon_name}  [{beacon_id[:8]}…]"
    elif beacon_name:
        title_str = f"{beacon_name}  [{beacon_id[:8]}…]"
    else:
        title_str = f"[{beacon_id}]"

    if matches:
        _log(app,
             f"  ✓ {len(matches)} observation match(es) found for {title_str}",
             "success")
    else:
        _log(app,
             f"  ⚠ No observation matches found for {title_str} in {csv_path}",
             "warning")

    win = tk.Toplevel(app.root)
    win.title(f"Observation Matches — {title_str}")
    win.geometry("1060x520")
    win.resizable(True, True)
    win.transient(app.root)

    # ---- Header ----
    hdr = tk.Frame(win, bg='#1e3a5f', pady=8)
    hdr.pack(fill='x')
    tk.Label(hdr, text=f"🔍  Observations.db Matches  |  {title_str}",
             bg='#1e3a5f', fg='white',
             font=('Helvetica', 12, 'bold')).pack(side='left', padx=12)
    count_text = f"{len(matches)} match(es)" if matches else "No matches"
    tk.Label(hdr, text=count_text,
             bg='#1e3a5f', fg='#aac4e0',
             font=('Helvetica', 10)).pack(side='right', padx=12)

    if not matches:
        msg = (
            "No PWj keys derived from this beacon's secondarySharedSecret\n"
            "matched any 28-byte advertisementData value in the selected CSV.\n\n"
            "Possible reasons:\n"
            "  • This beacon was not within BLE range of the scanning device\n"
            "    during the capture window.\n"
            "  • The Observations.db is from a different device than the one\n"
            "    that observed this beacon.\n"
            "  • The beacon was only seen in near-owner mode (6-byte ADV),\n"
            "    not in separated mode (28-byte ADV)."
        )
        tk.Label(win, text=msg, font=('Helvetica', 10),
                 justify='left', padx=20, pady=20).pack(anchor='w')
        return

    # ---- Treeview table ----
    cols = ('j', 'est_date', 'ble_derived', 'observed_mac', 'observed_time', 'pwj')
    col_cfg = {
        'j':            ('Day j',         60,  'center'),
        'est_date':     ('Est. Date *',  105,  'center'),
        'ble_derived':  ('Derived BLE',  160,  'center'),
        'observed_mac': ('Observed MAC', 160,  'center'),
        'observed_time':('Seen Time',    185,  'center'),
        'pwj':          ('PWj Hex (28 bytes)', 360, 'w'),
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
    style.configure('Treeview', font=('Courier', 9), rowheight=20)
    style.configure('Treeview.Heading', font=('Helvetica', 9, 'bold'))

    for col, (heading, width, anchor) in col_cfg.items():
        tree.heading(col, text=heading)
        tree.column(col, width=width, minwidth=40, anchor=anchor)

    for i, m in enumerate(matches):
        tag = 'even' if i % 2 == 0 else 'odd'
        tree.insert('', 'end', values=(
            m.day_index,
            m.estimated_date_str,
            m.ble_address_str,
            m.observed_mac,
            m.observed_time,
            m.pw_j_bytes.hex(),
        ), tags=(tag,))

    # ---- Bottom bar ----
    bar = tk.Frame(win, pady=6)
    bar.pack(fill='x', padx=8)

    tk.Label(
        bar,
        text=("* Est. Date is anchored to pairingDate + j days and may be offset if "
              "iOS rotated the secondarySharedSecret after pairing."),
        font=('Helvetica', 8), fg='#555555'
    ).pack(side='left')

    def export_csv():
        path = filedialog.asksaveasfilename(
            parent=win,
            defaultextension='.csv',
            filetypes=[('CSV files', '*.csv'), ('All files', '*.*')],
            initialfile=f'obs_matches_{beacon_id[:8]}.csv',
            title='Save Observation Matches CSV'
        )
        if not path:
            return
        from src.key_schedule_generator import KeyScheduleGenerator
        KeyScheduleGenerator.export_matches_csv(matches, beacon_id, path)
        messagebox.showinfo("Exported",
                            f"Matches saved to:\n{path}",
                            parent=win)
        _log(app, f"  ✓ Observation matches exported: {path}", "success")

    tk.Button(bar, text="📄  Export CSV", command=export_csv,
              font=('Helvetica', 10, 'bold'),
              padx=10, pady=3, cursor='hand2').pack(side='right')


# ---------------------------------------------------------------------------
# Results window
# ---------------------------------------------------------------------------

def _show_results(app, record, entries: list) -> None:
    """Display the generated key schedule in a scrollable results window."""
    beacon_id   = str(record.identifier or 'Unknown')
    beacon_name = record.custom_name or ''
    emoji       = record.emoji or ''

    if beacon_name and emoji:
        title_str = f"{emoji} {beacon_name}  [{beacon_id[:8]}…]"
    elif beacon_name:
        title_str = f"{beacon_name}  [{beacon_id[:8]}…]"
    else:
        title_str = f"[{beacon_id}]"

    _log(app, f"  ✓ Key schedule: {len(entries)} days for {title_str}", "success")

    win = tk.Toplevel(app.root)
    win.title(f"Key Schedule — {title_str}")
    win.geometry("980x580")
    win.resizable(True, True)
    win.transient(app.root)

    # ---- Header ----
    hdr = tk.Frame(win, bg='#1e3a5f', pady=8)
    hdr.pack(fill='x')
    tk.Label(hdr, text=f"🔑  Secondary Key Schedule  |  {title_str}",
             bg='#1e3a5f', fg='white',
             font=('Helvetica', 12, 'bold')).pack(side='left', padx=12)
    tk.Label(hdr, text=f"{len(entries)} days",
             bg='#1e3a5f', fg='#aac4e0',
             font=('Helvetica', 10)).pack(side='right', padx=12)

    # ---- Treeview table ----
    cols = ('day', 'date', 'ble_addr', 'pw_j', 'payload', 'hint')
    col_cfg = {
        'day':      ('Step j',                55,  'center'),
        'date':     ('Est. Date * (4 AM)',   130,  'center'),
        'ble_addr': ('BLE Address',          165,  'center'),
        'pw_j':     ('PWj Hex (28 bytes)',   355,  'w'),
        'payload':  ('Payload Hex (22 b)',   265,  'w'),
        'hint':     ('Hint',                  50,  'center'),
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
    style.configure('Treeview', font=('Courier', 9), rowheight=20)
    style.configure('Treeview.Heading', font=('Helvetica', 9, 'bold'))

    for col, (heading, width, anchor) in col_cfg.items():
        tree.heading(col, text=heading)
        tree.column(col, width=width, minwidth=40, anchor=anchor)

    tree.tag_configure('even')
    tree.tag_configure('odd')

    for i, e in enumerate(entries):
        tag = 'even' if i % 2 == 0 else 'odd'
        tree.insert('', 'end', values=(
            e.day_index,
            e.date_str,
            e.ble_address_str,
            e.pw_j_bytes.hex(),
            e.payload_bytes.hex(),
            f'{e.key_hint_bits:02b}',
        ), tags=(tag,))

    # ---- Bottom bar ----
    bar = tk.Frame(win, pady=8)
    bar.pack(fill='x', padx=8)

    tk.Label(
        bar,
        text=("* Est. Date = pairingDate + j days from the stored checkpoint.  "
              "iOS periodically rotates the secondarySharedSecret, so the checkpoint "
              "may be days or weeks ahead of pairingDate — dates are approximate.  "
              "Use 'Compare vs Observations' for a forensically reliable timestamp."),
        font=('Helvetica', 8), fg='#555555', wraplength=860, justify='left'
    ).pack(side='left')

    def export_csv():
        path = filedialog.asksaveasfilename(
            parent=win,
            defaultextension='.csv',
            filetypes=[('CSV files', '*.csv'), ('All files', '*.*')],
            initialfile=f'key_schedule_{beacon_id[:8]}.csv',
            title='Save Key Schedule CSV'
        )
        if not path:
            return
        from src.key_schedule_generator import KeyScheduleGenerator
        KeyScheduleGenerator.export_csv(entries, beacon_id, path)
        messagebox.showinfo("Exported",
                            f"Key schedule saved to:\n{path}",
                            parent=win)
        _log(app, f"  ✓ Key schedule exported: {path}", "success")

    tk.Button(bar, text="📄  Export CSV", command=export_csv,
              font=('Helvetica', 10, 'bold'),
              padx=10, pady=3, cursor='hand2').pack(side='right')


# ---------------------------------------------------------------------------
# Logging helper
# ---------------------------------------------------------------------------

def _log(app, message: str, tag: str = "") -> None:
    """Write to the GUI log via app._log(), falling back to print()."""
    try:
        app._log(message, tag)
    except Exception:
        print(message)
