"""
key_schedule_generator.py
=========================
Generates the BLE advertisement key schedule for a Find My beacon in
separated state, using the secondary key (SKS) derivation chain defined
in Apple's Find My Network Accessory Specification R2, Section 6.3.4.

In separated state an AirTag or third-party beacon cycles through daily
advertisement keys (PWj). Each PWj encodes the BLE device address and
manufacturer payload that the tag will broadcast for a 24-hour window
(from 4 AM local time to the next 4 AM).

Knowing P (the master public key) and SKS0 (the secondary shared secret)
— both present in decrypted OwnedBeacon plists — we can reconstruct every
advertisement key for any date range. This allows forensic examiners to
cross-reference captured BLE scans, iOS unwanted-tracker alert logs, or
third-party detector app exports against a specific beacon.

Derivation chain (per spec Section 6.3.4.2):
    SKSj = ANSI-X9.63-KDF(SKSj-1, "update")          [32 bytes]
    ATj  = ANSI-X9.63-KDF(SKSj,   "diversify")        [72 bytes -> uj||vj]
    uj   = (uj_raw mod (q-1)) + 1                      [valid P-224 scalar]
    vj   = (vj_raw mod (q-1)) + 1                      [valid P-224 scalar]
    PWj  = uj*P + vj*G                                 [P-224 point]

Advertisement encoding (per spec Section 5.1.3):
    BLE address   = PWj[0:6]  with bits 6-7 of byte 0 forced to 0b11
    Payload[3:24] = PWj[6:28]
    Payload[25] bits 0-1 = PWj[0] bits 6-7  (key hint)

Important note on date accuracy
-------------------------------
The secondarySharedSecret stored in an OwnedBeacon plist may have been
rotated by iOS after the original pairing.  When this happens, j=1 no
longer corresponds to pairingDate — the actual anchor date is unknown.
Dates produced by generate() should be treated as approximate.

For Observations.db correlation use search_observations() instead: it
always scans from j=1 to max_days without any date-range filter, so it
finds the correct PWj regardless of whether the secret has been rotated.
"""

import csv
import hashlib
from datetime import datetime, timedelta
from typing import List, Optional, Tuple

# ---------------------------------------------------------------------------
# Optional fast EC backend — uses OpenSSL (via the cryptography library)
# for scalar multiplication, which is 50-100x faster than the pure Python
# fallback below.  The cryptography library is already a project dependency,
# so this import should always succeed.  If for any reason it fails the code
# falls back silently to the pure Python implementation.
# ---------------------------------------------------------------------------
try:
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False


# ---------------------------------------------------------------------------
# P-224 curve parameters (NIST P-224 / secp224r1)
# Reference: FIPS 186-4, D.1.2.2
# ---------------------------------------------------------------------------
_P   = 2**224 - 2**96 + 1
_N   = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D
_A   = _P - 3
_B   = 0xB4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4
_GX  = 0xB70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21
_GY  = 0xBD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34
_G   = (_GX, _GY)

# Type alias: a curve point is (x, y) or None (point at infinity)
Point = Optional[Tuple[int, int]]


# ---------------------------------------------------------------------------
# Minimal P-224 arithmetic
# ---------------------------------------------------------------------------

def _modinv(a: int, m: int) -> int:
    """Modular multiplicative inverse via extended Euclidean algorithm."""
    a = a % m
    g, x = _egcd(a, m)[:2]
    if g != 1:
        raise ValueError("No modular inverse exists")
    return x % m


def _egcd(a: int, b: int) -> Tuple[int, int, int]:
    if a == 0:
        return b, 0, 1
    g, x, y = _egcd(b % a, a)
    return g, y - (b // a) * x, x


def _point_add(P: Point, Q: Point) -> Point:
    """Add two P-224 points (handles point at infinity and doubling)."""
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2:
        if y1 != y2:
            return None  # P + (-P) = point at infinity
        # Point doubling
        lam = (3 * x1 * x1 + _A) * _modinv(2 * y1, _P) % _P
    else:
        lam = (y2 - y1) * _modinv(x2 - x1, _P) % _P
    x3 = (lam * lam - x1 - x2) % _P
    y3 = (lam * (x1 - x3) - y1) % _P
    return (x3, y3)


def _scalar_mult(k: int, P: Point) -> Point:
    """Multiply a P-224 point by scalar k (double-and-add)."""
    if k == 0 or P is None:
        return None
    if k < 0:
        k = -k
        P = (P[0], (-P[1]) % _P)
    result: Point = None
    addend = P
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result


# ---------------------------------------------------------------------------
# ANSI X9.63 Key Derivation Function (SHA-256)
# Reference: SEC1, Section 3.6.1
# ---------------------------------------------------------------------------

def _kdf(z: bytes, shared_info: bytes, length: int) -> bytes:
    """ANSI X9.63 KDF using SHA-256 as the hash function."""
    output = b''
    counter = 1
    while len(output) < length:
        output += hashlib.sha256(
            z + counter.to_bytes(4, 'big') + shared_info
        ).digest()
        counter += 1
    return output[:length]


# ---------------------------------------------------------------------------
# Data class for a single day's key entry
# ---------------------------------------------------------------------------

class KeyScheduleEntry:
    """
    Represents a single 24-hour secondary advertisement key (PWj).

    Attributes
    ----------
    day_index       : int      - The j index (1-based) relative to pairing date.
    date            : datetime - The date this key activates (at 4 AM local).
    ble_address     : bytes    - 6-byte BLE advertisement address.
    pw_j_bytes      : bytes    - 28-byte x-coordinate of PWj point.
    payload_bytes   : bytes    - 22 bytes that appear in manufacturer payload.
    key_hint_bits   : int      - 2-bit value embedded in payload byte 25.
    """

    def __init__(self, day_index: int, date: datetime,
                 pw_j_point: Tuple[int, int]):
        self.day_index = day_index
        self.date = date

        # Encode PWj as 28-byte big-endian x-coordinate
        self.pw_j_bytes = pw_j_point[0].to_bytes(28, 'big')

        # BLE address: PWj[0:6] with bits 6-7 of byte 0 set to 0b11
        # (static random address type, per spec Section 5.1.3 and Bluetooth SIG)
        addr = bytearray(self.pw_j_bytes[0:6])
        addr[0] = (addr[0] & 0x3F) | 0xC0
        self.ble_address = bytes(addr)

        # Manufacturer payload bytes: PWj[6:28]
        self.payload_bytes = self.pw_j_bytes[6:28]

        # 2-bit key hint: bits 6-7 of PWj[0], placed in payload byte 25
        self.key_hint_bits = (self.pw_j_bytes[0] >> 6) & 0x03

    @property
    def ble_address_str(self) -> str:
        """BLE address as colon-separated uppercase hex (e.g. 'F9:5C:67:49:38:11')."""
        return ':'.join(f'{b:02X}' for b in self.ble_address)

    @property
    def date_str(self) -> str:
        return self.date.strftime('%Y-%m-%d')

    def __str__(self) -> str:
        return (
            f"Day {self.day_index:>4}  {self.date_str}  "
            f"BLE: {self.ble_address_str}  "
            f"PWj: {self.pw_j_bytes.hex()}"
        )


# ---------------------------------------------------------------------------
# Match result returned by search_observations()
# ---------------------------------------------------------------------------

class ObservationMatch:
    """
    A confirmed match between a derived PWj and an Observations.db row.

    Attributes
    ----------
    day_index       : int      - Derivation step j at which the match was found.
    estimated_date  : datetime - Date estimate anchored to pairingDate + j days.
                                 WARNING: may be offset if secondarySharedSecret
                                 was rotated after pairing.  Use as a rough
                                 reference only, not a forensic timestamp.
    pw_j_bytes      : bytes    - The 28-byte PWj x-coordinate that matched.
    ble_address_str : str      - 6-byte BLE MAC derived from PWj (colon hex).
    observed_mac    : str      - MAC_Address value from the Observations.db row.
    observed_time   : str      - Seen_Time from the Observations.db row.
    """

    def __init__(self, day_index: int, estimated_date: datetime,
                 pw_j_bytes: bytes, observed_mac: str = '',
                 observed_time: str = ''):
        self.day_index      = day_index
        self.estimated_date = estimated_date
        self.pw_j_bytes     = pw_j_bytes

        addr = bytearray(pw_j_bytes[0:6])
        addr[0] = (addr[0] & 0x3F) | 0xC0
        self.ble_address_str = ':'.join(f'{b:02X}' for b in addr)

        self.observed_mac  = observed_mac
        self.observed_time = observed_time

    @property
    def estimated_date_str(self) -> str:
        return self.estimated_date.strftime('%Y-%m-%d')

    def __str__(self) -> str:
        return (
            f"Match j={self.day_index}  est.date={self.estimated_date_str}  "
            f"BLE={self.ble_address_str}  observed={self.observed_time}"
        )


# ---------------------------------------------------------------------------
# Main generator class
# ---------------------------------------------------------------------------

class KeyScheduleGenerator:
    """
    Generates the secondary key (PWj) schedule for a paired Find My beacon.

    Parameters
    ----------
    public_key_bytes : bytes
        57-byte uncompressed P-224 public key (0x04 || x[28] || y[28]).
        Taken from OwnedBeacon plist field: publicKey.key.data
    sks0 : bytes
        32-byte secondary shared secret (SKS0).
        Taken from OwnedBeacon plist field: secondarySharedSecret.key.data
    pairing_date : datetime
        When the beacon was first paired to its owner device.
        Taken from OwnedBeacon plist field: pairingDate
    """

    def __init__(self, public_key_bytes: bytes, sks0: bytes,
                 pairing_date: datetime, d0: bytes = None):
        if len(public_key_bytes) != 57 or public_key_bytes[0] != 0x04:
            raise ValueError(
                "Expected 57-byte uncompressed P-224 key (04 || x || y)"
            )
        # Parse the master public key point P
        x = int.from_bytes(public_key_bytes[1:29], 'big')
        y = int.from_bytes(public_key_bytes[29:57], 'big')
        self._P: Point = (x, y)
        self._sks0 = sks0
        self._pairing_date = pairing_date

        # Fast-path scalar: store d0 as an integer so _derive_pw_j can use
        # the OpenSSL-backed path (d_j = d0×u + v mod N, then d_j×G via
        # cryptography library) instead of the slower pure Python EC math.
        # d0 is the 28-byte P-224 private scalar from OwnedBeaconRecord.
        if d0 is not None and _CRYPTO_AVAILABLE and len(d0) == 28:
            self._d0: Optional[int] = int.from_bytes(d0, 'big')
        else:
            self._d0 = None

    def _first_4am_after(self, dt: datetime) -> datetime:
        """Return the first 4 AM (local) strictly after the given datetime."""
        candidate = dt.replace(hour=4, minute=0, second=0, microsecond=0)
        if dt.hour >= 4:
            candidate += timedelta(days=1)
        return candidate

    def _derive_pw_j(self, sks_j: bytes) -> Tuple[int, int]:
        """Derive PWj elliptic curve point from current SKSj.

        Uses the fast OpenSSL path when d0 (the master private scalar) is
        available:
            d_j = (d0 × u + v) mod N        ← pure integer math, instant
            p_j = d_j × G                   ← one EC multiply via OpenSSL

        Falls back to the original pure Python path (two EC multiplies) when
        d0 was not supplied or the cryptography library is unavailable.
        """
        at_j = _kdf(sks_j, b'diversify', 72)
        u_raw = int.from_bytes(at_j[0:36], 'big')
        v_raw = int.from_bytes(at_j[36:72], 'big')
        u = (u_raw % (_N - 1)) + 1
        v = (v_raw % (_N - 1)) + 1

        if self._d0 is not None:
            # Fast path -------------------------------------------------------
            # Compute the rolling private scalar directly.
            # This is the math Apple uses internally (from the spec):
            #   d_j = (d0 × u + v) mod N
            # Then derive the public point from it.  One OpenSSL call replaces
            # two pure-Python scalar multiplications.
            d_j = (self._d0 * u + v) % _N
            priv = _ec.derive_private_key(d_j, _ec.SECP224R1())
            pub_nums = priv.public_key().public_numbers()
            return (pub_nums.x, pub_nums.y)
        else:
            # Slow fallback (no d0 available) ---------------------------------
            uj_P = _scalar_mult(u, self._P)
            vj_G = _scalar_mult(v, _G)
            pw_j = _point_add(uj_P, vj_G)
            if pw_j is None:
                raise ValueError("PWj derived as point at infinity — unexpected")
            return pw_j

    def generate(self, start_date: datetime, end_date: datetime,
                 progress_callback=None) -> List[KeyScheduleEntry]:
        """
        Generate one KeyScheduleEntry per day in [start_date, end_date].

        The first secondary key (PWj=1) activates at the first 4 AM local
        time after pairing. Each day thereafter a new key activates at 4 AM.
        Date range is inclusive on both ends.

        Parameters
        ----------
        start_date       : datetime - First day of interest.
        end_date         : datetime - Last day of interest (inclusive).
        progress_callback: callable(current, total) - Optional progress hook.

        Returns
        -------
        List[KeyScheduleEntry] sorted chronologically.
        """
        # Anchor: first 4 AM after pairing = when PWj=1 first becomes active
        first_4am = self._first_4am_after(self._pairing_date)

        # Align start to 4 AM
        start_4am = start_date.replace(
            hour=4, minute=0, second=0, microsecond=0
        )
        end_4am = end_date.replace(
            hour=4, minute=0, second=0, microsecond=0
        )

        # How many complete 24-hour periods from first_4am to start_4am?
        days_offset = max(0, (start_4am - first_4am).days)
        start_j = days_offset + 1  # j is 1-based

        total_days = max(0, (end_4am - start_4am).days) + 1

        # Fast-forward SKS to start_j by applying "update" KDF (start_j) times
        sks = self._sks0
        for _ in range(start_j):
            sks = _kdf(sks, b'update', 32)

        entries: List[KeyScheduleEntry] = []
        current_4am = start_4am
        j = start_j

        for i in range(total_days):
            if progress_callback:
                progress_callback(i + 1, total_days)

            pw_j = self._derive_pw_j(sks)
            entries.append(KeyScheduleEntry(j, current_4am, pw_j))

            # Advance
            sks = _kdf(sks, b'update', 32)
            current_4am += timedelta(days=1)
            j += 1

        return entries

    def search_observations(
        self,
        adv_data_targets: List[Tuple[str, str, str]],
        max_days: int = 3000,
        progress_callback=None,
    ) -> List[ObservationMatch]:
        """
        Search all derived PWj keys for matches against Observations.db rows.

        Unlike generate(), this method ALWAYS starts from j=1 and applies NO
        date-range filter.  This is the correct approach for Observations.db
        correlation because the secondarySharedSecret may have been rotated
        by iOS after pairing, making the pairingDate-anchored offset unreliable.
        A pure byte-match scan finds the correct key regardless of rotation.

        Parameters
        ----------
        adv_data_targets : list of (adv_hex, mac_str, seen_time) tuples
            Each entry represents one row from Observations.db:
              adv_hex   — advertisementData as a 56-char hex string (28 bytes)
              mac_str   — MAC_Address string (carried through for display)
              seen_time — Seen_Time string (carried through for display)
        max_days : int
            Maximum derivation steps to try (default 3000, roughly 8 years).
        progress_callback : callable(current, total), optional
            Called every 50 steps with (j, max_days) for progress reporting.

        Returns
        -------
        List[ObservationMatch] in ascending j order.
        The estimated_date on each match is anchored to pairingDate + j days
        and should be treated as approximate when the secret has been rotated.
        """
        # Build fast lookup: normalised_hex -> (mac_str, seen_time)
        target_map: dict = {}
        for adv_hex, mac_str, seen_time in adv_data_targets:
            normalised = adv_hex.lower().replace(' ', '').replace(':', '')
            if len(normalised) == 56:  # exactly 28 bytes
                target_map[normalised] = (mac_str, seen_time)

        if not target_map:
            return []

        # Estimate date anchor for labelling — may be offset if secret rotated
        first_4am = self._first_4am_after(self._pairing_date)

        matches: List[ObservationMatch] = []
        sks = self._sks0

        for j in range(1, max_days + 1):
            if progress_callback and j % 50 == 0:
                progress_callback(j, max_days)

            sks = _kdf(sks, b'update', 32)
            pw_j = self._derive_pw_j(sks)
            pw_j_bytes = pw_j[0].to_bytes(28, 'big')

            if pw_j_bytes.hex() in target_map:
                mac_str, seen_time = target_map[pw_j_bytes.hex()]
                estimated_date = first_4am + timedelta(days=j - 1)
                matches.append(ObservationMatch(
                    day_index      = j,
                    estimated_date = estimated_date,
                    pw_j_bytes     = pw_j_bytes,
                    observed_mac   = mac_str,
                    observed_time  = seen_time,
                ))

        return matches

    def search_by_ble_mac(
        self,
        mac_targets: List[Tuple[str, str]],
        max_days: int = 3000,
        progress_callback=None,
    ) -> List[ObservationMatch]:
        """
        Search all derived PWj keys for matches against a list of BLE MAC
        addresses.

        This is the separated-key equivalent of NearbyKeyScheduleGenerator's
        MAC-based search.  It is used when a Wild Mode record originated from
        an iOS 17 device but the stored advertisement payload is only 6 bytes
        (i.e. only the MAC portion was retained) rather than the full 28-byte
        PWj x-coordinate.  In that situation a direct hex comparison against
        the PWj bytes is impossible, so we instead derive the 6-byte BLE MAC
        from each PWj step and compare that.

        The BLE MAC is constructed from PWj exactly as the key schedule does:
            byte 0 of PWj -> byte 0 of MAC, with top two bits forced to 1
            (i.e. ``addr[0] = (addr[0] & 0x3F) | 0xC0``)
            bytes 1-5 of PWj -> bytes 1-5 of MAC (unchanged)

        Parameters
        ----------
        mac_targets : list of (mac_str, seen_time) tuples
            Each entry is one Wild Mode row from iOS 17 where only the
            Advertisement_MAC (and no full 28-byte Advertisement_Hex) is
            available.  ``mac_str`` is the colon-separated MAC as exported
            by Lost Apples (e.g. "C7:3D:7F:B5:70:D0").  The | 0xC0
            correction must already have been applied.
        max_days : int
            Maximum PWj derivation steps to try.
        progress_callback : callable(current, total), optional
            Called every 50 steps.

        Returns
        -------
        List[ObservationMatch] in ascending day-index order.
        ``pw_j_bytes`` on each match contains the full 28-byte PWj, which
        the caller can use for downstream display and CSV export.
        """
        # Build fast lookup: normalised 12-char uppercase hex -> (mac_str, ts)
        target_map: dict = {}
        for mac_str, seen_time in mac_targets:
            norm = (mac_str.upper()
                    .replace(':', '').replace('-', '').replace(' ', ''))
            if len(norm) == 12:  # exactly 6 bytes
                target_map[norm] = (mac_str, seen_time)

        if not target_map:
            return []

        first_4am = self._first_4am_after(self._pairing_date)

        matches: List[ObservationMatch] = []
        sks = self._sks0

        for j in range(1, max_days + 1):
            if progress_callback and j % 50 == 0:
                progress_callback(j, max_days)

            sks = _kdf(sks, b'update', 32)
            pw_j = self._derive_pw_j(sks)
            pw_j_bytes = pw_j[0].to_bytes(28, 'big')

            # Derive the 6-byte BLE MAC from the first 6 bytes of PWj,
            # applying the static-random address correction (| 0xC0).
            addr = bytearray(pw_j_bytes[0:6])
            addr[0] = (addr[0] & 0x3F) | 0xC0
            ble_norm = bytes(addr).hex().upper()

            if ble_norm in target_map:
                mac_str, seen_time = target_map[ble_norm]
                estimated_date = first_4am + timedelta(days=j - 1)
                matches.append(ObservationMatch(
                    day_index      = j,
                    estimated_date = estimated_date,
                    pw_j_bytes     = pw_j_bytes,
                    observed_mac   = mac_str,
                    observed_time  = seen_time,
                ))

        return matches

    @staticmethod
    def export_csv(entries: List[KeyScheduleEntry],
                   beacon_id: str, output_path: str) -> None:
        """
        Write key schedule to CSV.

        Columns
        -------
        Day_Index       - j index relative to pairing date
        Date_Active     - Date the key activates (at 4 AM local)
        BLE_Address     - 6-byte advertisement address (colon hex)
        PWj_Hex         - Full 28-byte x-coordinate of PWj
        Payload_Hex     - 22-byte manufacturer payload content (PWj[6:28])
        Key_Hint_Bits   - 2-bit value for payload byte 25 (binary string)
        """
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Beacon_ID', 'Day_Index', 'Date_Active_4AM',
                'BLE_Address', 'PWj_Hex', 'Payload_Hex', 'Key_Hint_Bits'
            ])
            for e in entries:
                writer.writerow([
                    beacon_id,
                    e.day_index,
                    e.date_str,
                    e.ble_address_str,
                    e.pw_j_bytes.hex(),
                    e.payload_bytes.hex(),
                    f'{e.key_hint_bits:02b}',
                ])

    @staticmethod
    def export_matches_csv(
        matches: List[ObservationMatch],
        beacon_id: str,
        output_path: str,
    ) -> None:
        """
        Write Observations.db match results to CSV.

        Columns
        -------
        Beacon_ID       - UUID of the OwnedBeacon
        Day_Index       - Derivation step j at which PWj was found
        Est_Date_Active - Estimated key activation date (pairingDate + j;
                          approximate — may be offset if secret was rotated)
        BLE_Address     - 6-byte advertisement MAC (colon hex)
        PWj_Hex         - Full 28-byte x-coordinate of matching PWj
        Observed_MAC    - MAC_Address from the Observations.db row
        Observed_Time   - Seen_Time from the Observations.db row
        """
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Beacon_ID', 'Day_Index', 'Est_Date_Active',
                'BLE_Address', 'PWj_Hex',
                'Observed_MAC', 'Observed_Time',
            ])
            for m in matches:
                writer.writerow([
                    beacon_id,
                    m.day_index,
                    m.estimated_date_str,
                    m.ble_address_str,
                    m.pw_j_bytes.hex(),
                    m.observed_mac,
                    m.observed_time,
                ])


# =============================================================================
# NEARBY KEY SCHEDULE
# =============================================================================
#
# These classes implement the PRIMARY key (Pi) derivation chain, used when a
# beacon is in "nearby" or "connected" state (i.e., near its owner device).
#
# The maths are identical to the separated (PWj) chain.  The only differences
# are:
#   • Seed         — sharedSecret (SKN0) instead of secondarySharedSecret (SKS0)
#   • Key label    — "Pi" instead of "PWj" in comments and UI
#   • Rotation     — every 15 minutes instead of every 24 hours
#   • Anchor time  — pairing_date directly (no "first 4 AM" adjustment)
#
# WHY the maths are the same
# --------------------------
# The Apple spec shows:
#     d_i = (d0 × u_i + v_i) mod N       where d0 = master private scalar
#     p_i = d_i × G
#
# Expanding that with d0 = private key and P = d0×G (master public key):
#     p_i = (d0×u_i + v_i) × G
#         = u_i×(d0×G) + v_i×G
#         = u_i×P + v_i×G            ← same formula as PWj in separated mode!
#
# So we can compute p_i from the PUBLIC key alone — no private key needed.
# This is intentional: it lets the server verify advertisements without
# knowing the private key.
# =============================================================================


class NearbyKeyScheduleEntry:
    """
    Represents a single 15-minute primary advertisement key (Pi).

    Attributes
    ----------
    step_index         : int      - The i index (1-based), relative to pairing date.
    estimated_datetime : datetime - Estimated activation time: pairing_date + i×15min.
                                    APPROXIMATE — iOS may rotate sharedSecret after pairing.
    p_i_bytes          : bytes    - 28-byte x-coordinate of the Pi elliptic curve point.
    ble_address        : bytes    - 6-byte BLE advertisement address derived from Pi.
    """

    def __init__(self, step_index: int, estimated_datetime: datetime,
                 p_i_point: Tuple[int, int]):
        self.step_index = step_index
        self.estimated_datetime = estimated_datetime

        # Encode Pi as 28-byte big-endian x-coordinate (same encoding as PWj)
        self.p_i_bytes = p_i_point[0].to_bytes(28, 'big')

        # BLE address: first 6 bytes of Pi, with bits 6-7 of byte 0 forced to 0b11.
        # This makes the address look like a Bluetooth "static random" address,
        # per the Bluetooth SIG specification and Apple Find My spec Section 5.1.3.
        addr = bytearray(self.p_i_bytes[0:6])
        addr[0] = (addr[0] & 0x3F) | 0xC0   # clear bits 6-7, then set both to 1
        self.ble_address = bytes(addr)

    @property
    def ble_address_str(self) -> str:
        """BLE address as colon-separated uppercase hex, e.g. 'F9:5C:67:49:38:11'."""
        return ':'.join(f'{b:02X}' for b in self.ble_address)

    @property
    def datetime_str(self) -> str:
        """Estimated activation datetime as 'YYYY-MM-DD HH:MM'."""
        return self.estimated_datetime.strftime('%Y-%m-%d %H:%M')

    def __str__(self) -> str:
        return (
            f"Step {self.step_index:>5}  {self.datetime_str}  "
            f"BLE: {self.ble_address_str}  "
            f"Pi: {self.p_i_bytes.hex()}"
        )


class NearbyObservationMatch:
    """
    A confirmed match between a derived Pi MAC address and an Observations.db row.

    Attributes
    ----------
    step_index         : int      - Derivation step i at which the match was found.
    estimated_datetime : datetime - Estimated activation time for step i.
                                    APPROXIMATE — iOS may rotate sharedSecret.
    p_i_bytes          : bytes    - The 28-byte Pi x-coordinate that matched.
    ble_address_str    : str      - Derived 6-byte BLE MAC (colon hex).
    observed_mac       : str      - MAC_Address value from the Observations.db row.
    observed_time      : str      - Seen_Time from the Observations.db row.
    """

    def __init__(self, step_index: int, estimated_datetime: datetime,
                 p_i_bytes: bytes, observed_mac: str = '',
                 observed_time: str = ''):
        self.step_index = step_index
        self.estimated_datetime = estimated_datetime
        self.p_i_bytes = p_i_bytes

        addr = bytearray(p_i_bytes[0:6])
        addr[0] = (addr[0] & 0x3F) | 0xC0
        self.ble_address_str = ':'.join(f'{b:02X}' for b in addr)

        self.observed_mac = observed_mac
        self.observed_time = observed_time

    @property
    def estimated_datetime_str(self) -> str:
        return self.estimated_datetime.strftime('%Y-%m-%d %H:%M')

    def __str__(self) -> str:
        return (
            f"Match i={self.step_index}  est.time={self.estimated_datetime_str}  "
            f"BLE={self.ble_address_str}  observed={self.observed_time}"
        )


class NearbyKeyScheduleGenerator:
    """
    Generates the primary key (Pi) schedule for a paired Find My beacon.

    This covers "nearby" and "connected" state — when the beacon is close
    to or connected to its owner's device.

    Parameters
    ----------
    public_key_bytes : bytes
        57-byte uncompressed P-224 public key (0x04 || x[28] || y[28]).
        Taken from OwnedBeacon plist field: publicKey.key.data
    skn0 : bytes
        32-byte primary shared secret (SKN0).
        Taken from OwnedBeacon plist field: sharedSecret.key.data
    pairing_date : datetime
        When the beacon was first paired to its owner device.
        Taken from OwnedBeacon plist field: pairingDate

    Key rotation
    ------------
    Primary keys rotate every 15 minutes.  The estimated datetime for step i is:
        pairing_date + i × 15 minutes
    This is APPROXIMATE — iOS may rotate sharedSecret after pairing, which
    shifts the effective anchor date.  Always label results as estimated.
    """

    # Default number of 15-minute steps to generate.
    # 672 = 7 days × 24 hours × 4 intervals per hour.
    DEFAULT_STEPS = 672

    def __init__(self, public_key_bytes: bytes, skn0: bytes,
                 pairing_date: datetime, d0: bytes = None):
        if len(public_key_bytes) != 57 or public_key_bytes[0] != 0x04:
            raise ValueError(
                "Expected 57-byte uncompressed P-224 key (04 || x || y)"
            )
        # Parse the master public key point P from the 57-byte blob.
        # Bytes 1-28 = x-coordinate, bytes 29-56 = y-coordinate (both big-endian).
        x = int.from_bytes(public_key_bytes[1:29], 'big')
        y = int.from_bytes(public_key_bytes[29:57], 'big')
        self._P: Point = (x, y)
        self._skn0 = skn0
        self._pairing_date = pairing_date

        # Fast-path scalar — same logic as KeyScheduleGenerator.
        # d0 is the 28-byte P-224 private scalar from OwnedBeaconRecord.
        if d0 is not None and _CRYPTO_AVAILABLE and len(d0) == 28:
            self._d0: Optional[int] = int.from_bytes(d0, 'big')
        else:
            self._d0 = None

    def _derive_p_i(self, sk_i: bytes) -> Tuple[int, int]:
        """
        Derive the Pi elliptic curve point from the current SKi value.

        Uses the fast OpenSSL path when d0 (the master private scalar) is
        available:
            d_i = (d0 × u + v) mod N        ← pure integer math, instant
            p_i = d_i × G                   ← one EC multiply via OpenSSL

        Falls back to the original pure Python path (two EC multiplies) when
        d0 was not supplied or the cryptography library is unavailable.
        """
        # Step 1: Run the "diversify" KDF to produce 72 bytes.
        at_i = _kdf(sk_i, b'diversify', 72)
        u_raw = int.from_bytes(at_i[0:36], 'big')
        v_raw = int.from_bytes(at_i[36:72], 'big')

        # Step 2: Reduce to valid P-224 scalars.
        u = (u_raw % (_N - 1)) + 1
        v = (v_raw % (_N - 1)) + 1

        if self._d0 is not None:
            # Fast path -------------------------------------------------------
            # d_i = (d0 × u + v) mod N — identical algebra to the separated
            # schedule; only the seed (SKN0 vs SKS0) differs.
            d_i = (self._d0 * u + v) % _N
            priv = _ec.derive_private_key(d_i, _ec.SECP224R1())
            pub_nums = priv.public_key().public_numbers()
            return (pub_nums.x, pub_nums.y)
        else:
            # Slow fallback (no d0 available) ---------------------------------
            u_P = _scalar_mult(u, self._P)
            v_G = _scalar_mult(v, _G)
            p_i = _point_add(u_P, v_G)
            if p_i is None:
                raise ValueError("Pi derived as point at infinity — unexpected")
            return p_i

    def generate(
        self,
        num_steps: int = DEFAULT_STEPS,
        progress_callback=None,
    ) -> List[NearbyKeyScheduleEntry]:
        """
        Generate a list of NearbyKeyScheduleEntry objects.

        Each entry covers one 15-minute window starting at:
            pairing_date + (i-1) × 15 minutes   (for step i)

        Parameters
        ----------
        num_steps : int
            Number of 15-minute steps to generate.
            Default 672 = exactly 7 days of coverage.
        progress_callback : callable(current, total), optional
            Called every 50 steps for progress reporting.

        Returns
        -------
        List[NearbyKeyScheduleEntry] in ascending step order.
        """
        entries: List[NearbyKeyScheduleEntry] = []
        sk = self._skn0                     # start from SKN0 (the sharedSecret seed)
        current_dt = self._pairing_date     # anchor to pairing date

        for i in range(1, num_steps + 1):
            if progress_callback and i % 50 == 0:
                progress_callback(i, num_steps)

            # Advance the key: SKi = KDF(SKi-1, "update", 32)
            sk = _kdf(sk, b'update', 32)

            # Derive the advertisement key point Pi
            p_i = self._derive_p_i(sk)

            entries.append(NearbyKeyScheduleEntry(i, current_dt, p_i))

            # Each step = 15 minutes
            current_dt += timedelta(minutes=15)

        return entries

    def search_observations(
        self,
        mac_targets: List[Tuple[str, str]],
        max_steps: int = 10000,
        progress_callback=None,
    ) -> List[NearbyObservationMatch]:
        """
        Search all derived Pi BLE MAC addresses against Observations.db rows.

        For nearby/connected state, the beacon advertisement carries only the
        6-byte MAC (the "short" advertisement format), so we compare derived
        MACs against the MAC_Address column in the Observations.db CSV export
        rather than the full advertisementData bytes used in separated mode.

        This method always starts from i=1 — no date filter is applied.
        This is the correct approach because sharedSecret may have been rotated
        by iOS after pairing, making the pairing_date anchor unreliable.

        Parameters
        ----------
        mac_targets : list of (mac_str, seen_time) tuples
            Each entry is one row from Observations.db:
              mac_str   — MAC_Address string, e.g. 'F9:5C:67:49:38:11'
              seen_time — Seen_Time string (carried through for display)
        max_steps : int
            Maximum number of 15-minute intervals to search (default 10000 ≈ 104 days).
        progress_callback : callable(current, total), optional
            Called every 50 steps for progress reporting.

        Returns
        -------
        List[NearbyObservationMatch] in ascending step order.
        """
        # Build a fast lookup dictionary.
        # Keys: normalised MAC as 12 uppercase hex chars (no separators), e.g. 'F95C67493811'
        # Values: (original mac_str, seen_time)
        target_map: dict = {}
        for mac_str, seen_time in mac_targets:
            # Normalise: strip colons, hyphens, spaces; uppercase
            normalised = mac_str.upper().replace(':', '').replace('-', '').replace(' ', '')
            if len(normalised) == 12:   # 6 bytes = 12 hex chars
                target_map[normalised] = (mac_str, seen_time)

        if not target_map:
            return []

        matches: List[NearbyObservationMatch] = []
        sk = self._skn0
        current_dt = self._pairing_date

        for i in range(1, max_steps + 1):
            if progress_callback and i % 50 == 0:
                progress_callback(i, max_steps)

            sk = _kdf(sk, b'update', 32)
            p_i = self._derive_p_i(sk)
            p_i_bytes = p_i[0].to_bytes(28, 'big')

            # Compute the derived BLE address for this step
            addr = bytearray(p_i_bytes[0:6])
            addr[0] = (addr[0] & 0x3F) | 0xC0
            ble_mac_normalised = bytes(addr).hex().upper()   # 12 uppercase hex chars

            if ble_mac_normalised in target_map:
                orig_mac, seen_time = target_map[ble_mac_normalised]
                matches.append(NearbyObservationMatch(
                    step_index=i,
                    estimated_datetime=current_dt,
                    p_i_bytes=p_i_bytes,
                    observed_mac=orig_mac,
                    observed_time=seen_time,
                ))

            current_dt += timedelta(minutes=15)

        return matches

    @staticmethod
    def export_csv(
        entries: List[NearbyKeyScheduleEntry],
        beacon_id: str,
        output_path: str,
    ) -> None:
        """
        Write nearby key schedule to CSV.

        Columns
        -------
        Beacon_ID        - UUID of the OwnedBeacon
        Step_Index       - i index relative to pairing date (1-based)
        Est_DateTime     - Estimated activation datetime (YYYY-MM-DD HH:MM) [APPROXIMATE]
        BLE_Address      - 6-byte advertisement address (colon hex)
        Pi_Hex           - Full 28-byte x-coordinate of Pi
        """
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Beacon_ID', 'Step_Index', 'Est_DateTime_APPROX',
                'BLE_Address', 'Pi_Hex',
            ])
            for e in entries:
                writer.writerow([
                    beacon_id,
                    e.step_index,
                    e.datetime_str,
                    e.ble_address_str,
                    e.p_i_bytes.hex(),
                ])

    @staticmethod
    def export_matches_csv(
        matches: List[NearbyObservationMatch],
        beacon_id: str,
        output_path: str,
    ) -> None:
        """
        Write nearby observation match results to CSV.

        Columns
        -------
        Beacon_ID        - UUID of the OwnedBeacon
        Step_Index       - Derivation step i at which Pi was found
        Est_DateTime     - Estimated activation datetime [APPROXIMATE]
        BLE_Address      - Derived 6-byte MAC (colon hex)
        Pi_Hex           - Full 28-byte x-coordinate of matching Pi
        Observed_MAC     - MAC_Address from the Observations.db row
        Observed_Time    - Seen_Time from the Observations.db row
        """
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Beacon_ID', 'Step_Index', 'Est_DateTime_APPROX',
                'BLE_Address', 'Pi_Hex',
                'Observed_MAC', 'Observed_Time',
            ])
            for m in matches:
                writer.writerow([
                    beacon_id,
                    m.step_index,
                    m.estimated_datetime_str,
                    m.ble_address_str,
                    m.p_i_bytes.hex(),
                    m.observed_mac,
                    m.observed_time,
                ])
