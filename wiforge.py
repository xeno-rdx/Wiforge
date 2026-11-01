#!/usr/bin/env python3
"""
Wiforge v4.1.0 — WPA/WPA2/WPA3 Capture Analyzer, Hash Extractor & Decryptor

CLI:
    Wiforge -a  <capture> [--full|--stats|--packets|--payloads] [-o f.json]
                                        Analyze capture (default)
    Wiforge -e  <capture> [--s PATH] [--format 22000,16800]
                                        Extract hashes to files
    Wiforge -i  <capture>              Inspect networks (no hash)
    Wiforge -sae <capture> [--s PATH]  WPA3-SAE operations
    Wiforge -ent <capture> [--creds] [--s PATH]
                                        802.1X Enterprise operations;
                                        --creds extracts real EAP-MD5 /
                                        EAP-MSCHAPv2 credentials, if any
    Wiforge -d  <capture> -p <pass> [--bssid MAC] [--sta MAC] [--s PATH]
                                        Decrypt traffic with a known password
    Wiforge --auto <capture> [-p <pass>] [--s PATH]
                                        Full pipeline: analyze->extract->decrypt
    Wiforge -m  <files...> -o <out>    Merge hash files
    Wiforge -c  <input> -o <output>    Convert between formats
    Wiforge -v  <file>                 Verify capture or hash file
    Wiforge -h                         Show help

Requires: Python 3 stdlib only, except -d/--auto -p which need
`cryptography` (pip install cryptography) for AES-CCM, AES key-unwrap and
AES-CMAC. `-ent --creds` needs wiforge_enterprise.py (stdlib only) in the
same directory as this script.

v4.0.1: -d/--auto auto-detect Key Descriptor Version and support the
*-SHA256 AKMs (PSK-SHA256, 802.1X-SHA256) via KDF-SHA256 + AES-128-CMAC.
TKIP (Key Descriptor Version 1) is still not implemented.

v4.1.0: `-ent --creds` now does real EAP-MD5 / EAP-MSCHAPv2 credential
extraction (not just detection), in the new wiforge_enterprise.py module
— writes hashcat -m 4800 / -m 5500 files. See that module's docstring for
exactly what it can and can't recover from a PEAP/TTLS-tunneled network.
"""

import argparse
import csv
import hashlib
import hmac
import io
import json
import os
import struct
import sys
import time
import threading
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

VERSION = "4.1.0"
PROG = "Wiforge"

# ============================================================================
# Optional crypto backend (needed only for -d / --decrypt and GTK unwrap)
# ============================================================================
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESCCM
    from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
    from cryptography.hazmat.primitives.cmac import CMAC
    from cryptography.hazmat.primitives.ciphers import algorithms
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

# Enterprise (802.1X) credential extraction — standalone module, stdlib
# only, kept in its own file (wiforge_enterprise.py, same directory) so
# it stays independently usable/testable. Everything else in Wiforge
# still works if it's missing; only `-ent --creds` needs it.
try:
    import wiforge_enterprise as _ent
    ENTERPRISE_MODULE_AVAILABLE = True
except ImportError:
    ENTERPRISE_MODULE_AVAILABLE = False

# ============================================================================
# Colors (auto-detect TTY)
# ============================================================================

class C:
    _enabled = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
    RESET  = "\033[0m"    if _enabled else ""
    BOLD   = "\033[1m"    if _enabled else ""
    DIM    = "\033[2m"    if _enabled else ""
    RED    = "\033[31m"   if _enabled else ""
    GREEN  = "\033[32m"   if _enabled else ""
    YELLOW = "\033[33m"   if _enabled else ""
    BLUE   = "\033[34m"   if _enabled else ""
    MAGENTA= "\033[35m"   if _enabled else ""
    CYAN   = "\033[36m"   if _enabled else ""
    WHITE  = "\033[37m"   if _enabled else ""


def ok(msg):    print(f"{C.GREEN}[+]{C.RESET} {msg}")
def warn(msg):  print(f"{C.YELLOW}[!]{C.RESET} {msg}")
def err(msg):   print(f"{C.RED}[-]{C.RESET} {msg}")
def info(msg):  print(f"{C.BLUE}[i]{C.RESET} {msg}")


# ============================================================================
# Banner
# ============================================================================

def banner():
    b = f"""{C.CYAN}{C.BOLD}
  ██╗    ██╗██╗███████╗ ██████╗ ██████╗  ██████╗ ███████╗
  ██║    ██║██║██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
  ██║ █╗ ██║██║█████╗  ██║   ██║██████╔╝██║  ███╗█████╗
  ██║███╗██║██║██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝
  ╚███╔███╔╝██║██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
   ╚══╝╚══╝ ╚═╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
{C.RESET}{C.DIM}  WPA/WPA2/WPA3 Capture Analyzer & Decryptor  —  v{VERSION}{C.RESET}
"""
    print(b)


# ============================================================================
# Progress bar
# ============================================================================

class ProgressBar:
    def __init__(self, total, prefix="Parsing", width=32, enable=True):
        self.total = max(total, 1)
        self.prefix = prefix
        self.width = width
        self.enable = enable
        self.current = 0
        self.start = time.time()
        self._lock = threading.Lock()

    def update(self, n=1):
        if not self.enable:
            return
        with self._lock:
            self.current += n
            self._draw()

    def _draw(self):
        pct = self.current / self.total
        filled = int(self.width * pct)
        bar = "█" * filled + "░" * (self.width - filled)
        elapsed = time.time() - self.start
        rate = self.current / elapsed if elapsed > 0 else 0
        eta = (self.total - self.current) / rate if rate > 0 else 0
        sys.stderr.write(
            f"\r{C.CYAN}{self.prefix}{C.RESET} |{C.GREEN}{bar}{C.RESET}| "
            f"{self.current}/{self.total} "
            f"[{rate:.0f}/s ETA {eta:.0f}s]"
        )
        sys.stderr.flush()

    def close(self):
        if self.enable and self.current < self.total:
            self.current = self.total
            self._draw()
            sys.stderr.write("\n")
            sys.stderr.flush()
        elif self.enable:
            sys.stderr.write("\n")
            sys.stderr.flush()


# ============================================================================
# Capture format constants
# ============================================================================

PCAP_MAGIC_LE = b"\xd4\xc3\xb2\xa1"
PCAP_MAGIC_BE = b"\xa1\xb2\xc3\xd4"
PCAPNG_MAGIC  = b"\x0a\x0d\x0d\x0a"

BT_IDB = 0x00000001
BT_SPB = 0x00000003
BT_EPB = 0x00000006

FT_MGMT = 0
FT_CTRL = 1
FT_DATA = 2

ST_ASSOC_REQ   = 0
ST_ASSOC_RESP  = 1
ST_REASSOC_REQ = 2
ST_REASSOC_RSP = 3
ST_PROBE_REQ   = 4
ST_PROBE_RESP  = 5
ST_BEACON      = 8
ST_ATIM        = 9
ST_DISASSOC    = 10
ST_AUTH        = 11
ST_DEAUTH      = 12

EAPOL_EAP_PACKET = 0
EAPOL_START      = 1
EAPOL_LOGOFF     = 2
EAPOL_KEY        = 3

SAE_AUTH_ALGO = 3
SAE_GROUP_19 = 19
SAE_GROUP_20 = 20
SAE_GROUP_21 = 21
SAE_STATUS_SUCCESS = 0
SAE_STATUS_SAE_HASH_TO_ELEMENT = 126


# ============================================================================
# Tables
# ============================================================================

CIPHER_MAP = {
    "000fac00": "Use-Group", "000fac01": "WEP-40", "000fac02": "TKIP",
    "000fac04": "CCMP-128", "000fac05": "WEP-104", "000fac08": "GCMP-128",
    "000fac09": "GCMP-256", "000fac0a": "CCMP-256", "000fac0b": "BIP-CMAC-128",
    "000fac0c": "BIP-GMAC-128", "000fac0d": "BIP-GMAC-256",
    "000fac0e": "BIP-CMAC-256",
}

AKM_MAP = {
    "000fac01": "802.1X", "000fac02": "PSK", "000fac03": "FT-802.1X",
    "000fac04": "FT-PSK", "000fac05": "802.1X-SHA256", "000fac06": "PSK-SHA256",
    "000fac07": "TDLS", "000fac08": "SAE", "000fac09": "FT-SAE",
    "000fac0a": "AP-PEER", "000fac0b": "802.1X-SUITE-B",
    "000fac0c": "802.1X-SUITE-B-192", "000fac0d": "FT-802.1X-SHA384",
    "000fac0e": "FILS-SHA256", "000fac0f": "FILS-SHA384",
    "000fac10": "FT-FILS-SHA256", "000fac11": "FT-FILS-SHA384",
    "000fac12": "OWE", "000fac13": "SAE-EXT-KEY", "000fac14": "FT-SAE-EXT-KEY",
    "000fac18": "OWE-TRANSITION",
    "0050f201": "WPA1-802.1X", "0050f202": "WPA1-PSK",
    "0050f203": "WPA1-802.1X-CCA", "0050f204": "WPA1-PSK-CCA",
}

AKM_PSK_CLASS    = {0x02, 0x04, 0x06}
AKM_8021X_CLASS  = {0x01, 0x03, 0x05}
AKM_SAE_CLASS    = {0x08, 0x09, 0x13, 0x14}
AKM_OWE_CLASS    = {0x12, 0x18}
AKM_FILS_CLASS   = {0x0e, 0x0f, 0x10, 0x11}
AKM_SUITE_B      = {0x0b, 0x0c, 0x0d}


# ============================================================================
# Utility
# ============================================================================

def mac(b):
    return ":".join(f"{x:02x}" for x in b)

def mac_hex(b):
    return b.hex()

def safe_decode(b):
    return b.decode("utf-8", "replace")


# ============================================================================
# Readers
# ============================================================================

class PcapReader:
    def __init__(self, path):
        self.f = open(path, "rb")
        header = self.f.read(24)
        if len(header) < 24:
            raise ValueError("truncated pcap header")
        magic = header[0:4]
        if magic == PCAP_MAGIC_LE:
            self.endian = "<"
        elif magic == PCAP_MAGIC_BE:
            self.endian = ">"
        else:
            raise ValueError("not a classic pcap file")
        self.network = struct.unpack(self.endian + "I", header[20:24])[0]

    def __iter__(self):
        return self

    def __next__(self):
        ph = self.f.read(16)
        if len(ph) < 16:
            raise StopIteration
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
            self.endian + "IIII", ph
        )
        pkt = self.f.read(incl_len)
        if len(pkt) < incl_len:
            raise StopIteration
        return self.network, ts_sec + ts_usec / 1_000_000.0, pkt

    def close(self):
        try: self.f.close()
        except Exception: pass


class PcapngReader:
    def __init__(self, path):
        self.f = open(path, "rb")
        self.endian = "<"
        self.interfaces = []

    def _read_exact(self, n):
        b = self.f.read(n)
        return b if len(b) == n else None

    def __iter__(self):
        return self

    def __next__(self):
        while True:
            hdr = self._read_exact(8)
            if hdr is None:
                raise StopIteration
            block_type = hdr[0:4]

            if block_type == PCAPNG_MAGIC:
                rest = self._read_exact(4)
                if rest is None: raise StopIteration
                bom = self._read_exact(4)
                if bom is None: raise StopIteration
                if bom == b"\x4d\x3c\x2b\x1a":
                    self.endian = "<"
                elif bom == b"\x1a\x2b\x3c\x4d":
                    self.endian = ">"
                else:
                    raise ValueError("bad pcapng byte-order magic")
                block_len = struct.unpack(self.endian + "I", rest)[0]
                remaining = block_len - 12
                if remaining > 0:
                    self._read_exact(remaining)
                self.interfaces = []
                continue

            block_len = struct.unpack(self.endian + "I", hdr[4:8])[0]
            if block_len < 12:
                raise ValueError("bad pcapng block length")

            if block_type == BT_IDB:
                body = self._read_exact(block_len - 12)
                if body is None: raise StopIteration
                linktype = struct.unpack(self.endian + "H", body[0:2])[0]
                self._read_exact(4)
                self.interfaces.append(linktype)
                continue

            if block_type == BT_EPB:
                body = self._read_exact(block_len - 12)
                if body is None: raise StopIteration
                iface_id, ts_high, ts_low, cap_len, orig_len = struct.unpack(
                    self.endian + "IIIII", body[0:20]
                )
                pkt = body[20:20 + cap_len]
                linktype = (self.interfaces[iface_id]
                            if iface_id < len(self.interfaces) else 105)
                ts = ((ts_high << 32) | ts_low) / 1_000_000.0
                self._read_exact(4)
                return linktype, ts, pkt

            if block_type == BT_SPB:
                body = self._read_exact(block_len - 12)
                if body is None: raise StopIteration
                orig_len = struct.unpack(self.endian + "I", body[0:4])[0]
                pkt = body[4:4 + orig_len]
                linktype = self.interfaces[0] if self.interfaces else 105
                self._read_exact(4)
                return linktype, 0.0, pkt

            if block_len - 12 > 0:
                self._read_exact(block_len - 12)
            self._read_exact(4)

    def close(self):
        try: self.f.close()
        except Exception: pass


def open_reader(path):
    with open(path, "rb") as f:
        magic = f.read(4)
    if magic == PCAPNG_MAGIC:
        return PcapngReader(path)
    if magic in (PCAP_MAGIC_LE, PCAP_MAGIC_BE):
        return PcapReader(path)
    raise ValueError("unknown capture format")


# ============================================================================
# Radiotap
# ============================================================================

RADIOTAP_FIELDS = [
    (0, "tsft", 8, 8), (1, "flags", 1, 1), (2, "rate", 1, 1),
    (3, "channel", 4, 2), (4, "fhss", 2, 2), (5, "dbm_antsignal", 1, 1),
    (6, "dbm_antnoise", 1, 1), (7, "lock_quality", 2, 2),
    (8, "tx_attenuation", 2, 2), (9, "db_tx_atten", 2, 2),
    (10, "dbm_tx_power", 1, 1), (11, "ant_signal", 1, 1),
    (12, "ant_noise", 1, 1), (13, "rx_flags", 2, 2), (14, "tx_flags", 2, 2),
    (15, "rts_retries", 1, 1), (16, "data_retries", 1, 1),
    (17, "xchannel", 8, 4), (18, "mcs", 3, 1), (19, "ampdu_status", 8, 4),
    (20, "vht", 12, 2), (21, "timestamp", 12, 8), (22, "he", 12, 2),
    (23, "he_mu", 12, 2), (24, "zero_len_psdu", 1, 1), (25, "lsig", 4, 2),
]

RF_CHAN_6GHZ = 0x0400
RF_CHAN_5GHZ = 0x0100
RF_CHAN_2GHZ = 0x0200


def parse_radiotap(pkt):
    out = {"chan_freq": None, "chan_flags": None, "band": None, "body": pkt}
    if len(pkt) < 8 or pkt[0] != 0x00 or pkt[1] != 0x00:
        return out
    rt_len = struct.unpack_from("<H", pkt, 2)[0]
    if rt_len < 8 or rt_len > len(pkt):
        return out
    out["body"] = pkt[rt_len:]

    offset = 4
    present_words = []
    while offset + 4 <= rt_len:
        word = struct.unpack_from("<I", pkt, offset)[0]
        present_words.append(word)
        offset += 4
        if not (word & 0x80000000):
            break

    present_bits = set()
    for wi, word in enumerate(present_words):
        for bit in range(32):
            if bit == 31 and wi < len(present_words) - 1:
                continue
            if word & (1 << bit):
                present_bits.add(wi * 32 + bit)

    field_off = offset
    for bit, name, size, align in RADIOTAP_FIELDS:
        if bit not in present_bits:
            continue
        field_off = (field_off + align - 1) & ~(align - 1)
        if field_off + size > rt_len:
            return out
        if name == "channel":
            freq, flags = struct.unpack_from("<HH", pkt, field_off)
            out["chan_freq"] = freq
            out["chan_flags"] = flags
            if flags & RF_CHAN_6GHZ:   out["band"] = "6GHz"
            elif flags & RF_CHAN_5GHZ: out["band"] = "5GHz"
            elif flags & RF_CHAN_2GHZ: out["band"] = "2GHz"
        field_off += size
    return out


def freq_to_channel(freq, band=None):
    if freq is None: return None
    if 2412 <= freq <= 2472: return (freq - 2407) // 5
    if freq == 2484: return 14
    if 5000 <= freq <= 5895: return (freq - 5000) // 5
    if 5955 <= freq <= 7115: return (freq - 5950) // 5
    return None


# ============================================================================
# 802.11 header
# ============================================================================

def parse_80211_header(pkt):
    if len(pkt) < 24:
        return None
    fc = struct.unpack_from("<H", pkt, 0)[0]
    ftype   = (fc >> 2) & 0x3
    subtype = (fc >> 4) & 0xF
    to_ds   = (fc >> 8) & 1
    from_ds = (fc >> 9) & 1
    more_frag = (fc >> 10) & 1
    retry   = (fc >> 11) & 1
    protected = (fc >> 14) & 1
    order   = (fc >> 15) & 1

    hdr_len = 24
    if to_ds and from_ds:
        hdr_len = 30
    if ftype == FT_DATA and (subtype & 0x8):
        hdr_len += 2
        if order:
            hdr_len += 4

    if len(pkt) < hdr_len:
        return None

    return {
        "fc": fc, "ftype": ftype, "subtype": subtype,
        "to_ds": to_ds, "from_ds": from_ds, "more_frag": more_frag,
        "retry": retry, "protected": protected, "order": order,
        "addr1": pkt[4:10], "addr2": pkt[10:16], "addr3": pkt[16:22],
        "seq": struct.unpack_from("<H", pkt, 22)[0] if len(pkt) >= 24 else 0,
        "hdr_len": hdr_len,
    }


# ============================================================================
# Fragment reassembly
# ============================================================================

class FragBuffer:
    def __init__(self, max_entries=64):
        self.buf = {}
        self.pktno = 0
        self.max_entries = max_entries
        self.last_frag_seq = {}

    @staticmethod
    def _key(h):
        tid = h["subtype"] & 0x7
        seq = h["seq"] >> 4
        return (bytes(h["addr2"]), tid, seq)

    def push(self, h, body):
        self.pktno += 1
        if len(self.buf) > self.max_entries:
            items = sorted(self.buf.items(), key=lambda kv: kv[1][1])
            for k, _ in items[:len(items) - self.max_entries]:
                self.buf.pop(k, None)
        key = self._key(h)
        frag_seq = h["seq"]
        if h["retry"] and self.last_frag_seq.get(key) == frag_seq:
            return None
        self.last_frag_seq[key] = frag_seq

        if h["more_frag"]:
            if key not in self.buf:
                self.buf[key] = (bytearray(), self.pktno)
            self.buf[key][0].extend(body)
            self.buf[key] = (self.buf[key][0], self.pktno)
            return None
        else:
            if key in self.buf:
                data, _ = self.buf.pop(key)
                return bytes(data) + body
            return body


# ============================================================================
# IE parsers
# ============================================================================

def parse_rsn_ie(ie_data):
    out = {
        "version": None, "group_cipher": None, "pairwise": [],
        "akm_suites": [], "rsn_caps": 0, "pmkid": None, "pmkids": [],
        "group_mgmt_cipher": None, "ext_rsn_caps": None,
    }
    try:
        pos = 0
        if pos + 2 > len(ie_data): return out
        out["version"] = struct.unpack_from("<H", ie_data, pos)[0]
        pos += 2
        if out["version"] != 1: return out
        if pos + 4 > len(ie_data): return out
        out["group_cipher"] = ie_data[pos:pos + 4].hex()
        pos += 4
        if pos + 2 > len(ie_data): return out
        pw_count = struct.unpack_from("<H", ie_data, pos)[0]
        pos += 2
        for _ in range(pw_count):
            if pos + 4 > len(ie_data): return out
            out["pairwise"].append(ie_data[pos:pos + 4].hex())
            pos += 4
        if pos + 2 > len(ie_data): return out
        akm_count = struct.unpack_from("<H", ie_data, pos)[0]
        pos += 2
        for _ in range(akm_count):
            if pos + 4 > len(ie_data): return out
            out["akm_suites"].append(ie_data[pos:pos + 4].hex())
            pos += 4
        if pos + 2 > len(ie_data): return out
        out["rsn_caps"] = struct.unpack_from("<H", ie_data, pos)[0]
        pos += 2
        if pos + 2 > len(ie_data): return out
        pmkid_count = struct.unpack_from("<H", ie_data, pos)[0]
        pos += 2
        for _ in range(pmkid_count):
            if pos + 16 > len(ie_data): return out
            out["pmkids"].append(ie_data[pos:pos + 16])
            pos += 16
        if out["pmkids"]:
            out["pmkid"] = out["pmkids"][0]
        if pos + 4 <= len(ie_data):
            out["group_mgmt_cipher"] = ie_data[pos:pos + 4].hex()
        if pos + 6 <= len(ie_data):
            out["ext_rsn_caps"] = struct.unpack_from("<H", ie_data, pos + 2)[0]
    except struct.error:
        pass
    return out


def parse_wpa1_ie(ie_data):
    out = {"group_cipher": None, "pairwise": [], "akm_suites": []}
    try:
        if len(ie_data) < 12: return out
        if ie_data[0:3] != b"\x00\x50\xf2" or ie_data[3] != 0x01:
            return out
        pos = 4
        pos += 2  # version
        if pos + 4 > len(ie_data): return out
        out["group_cipher"] = ie_data[pos:pos + 4].hex()
        pos += 4
        if pos + 2 > len(ie_data): return out
        pw_count = struct.unpack_from("<H", ie_data, pos)[0]
        pos += 2
        for _ in range(pw_count):
            if pos + 4 > len(ie_data): return out
            out["pairwise"].append(ie_data[pos:pos + 4].hex())
            pos += 4
        if pos + 2 > len(ie_data): return out
        akm_count = struct.unpack_from("<H", ie_data, pos)[0]
        pos += 2
        for _ in range(akm_count):
            if pos + 4 > len(ie_data): return out
            out["akm_suites"].append(ie_data[pos:pos + 4].hex())
            pos += 4
    except struct.error:
        pass
    return out


def classify_security(rsn, wpa1=None):
    akm_hexes = []
    if rsn and rsn.get("akm_suites"):
        akm_hexes = rsn["akm_suites"]
    elif wpa1 and wpa1.get("akm_suites"):
        akm_hexes = wpa1["akm_suites"]
    if not akm_hexes:
        return "Open"

    types = set()
    for a in akm_hexes:
        a = a.lower()
        if a.startswith("000fac") or a.startswith("0050f2"):
            types.add(int(a[-2:], 16))

    has_sae     = bool(types & AKM_SAE_CLASS)
    has_psk     = bool(types & AKM_PSK_CLASS)
    has_8021x   = bool(types & AKM_8021X_CLASS)
    has_owe     = bool(types & AKM_OWE_CLASS)
    has_fils    = bool(types & AKM_FILS_CLASS)
    has_suite_b = bool(types & AKM_SUITE_B)

    if wpa1 and not rsn:
        if has_psk:   return "WPA1-PSK"
        if has_8021x: return "WPA1-Enterprise"
        return "WPA1-PSK"
    if has_owe:
        return "OWE-Transition" if (has_psk or has_8021x or has_sae) else "OWE"
    if has_fils:     return "FILS"
    if has_suite_b:  return "WPA3-Enterprise"
    if has_sae and has_psk: return "WPA2/WPA3-Transition"
    if has_sae:
        if 0x13 in types or 0x14 in types: return "WPA3-SAE-EXT"
        return "WPA3-SAE"
    if has_psk:   return "WPA2-PSK"
    if has_8021x: return "WPA2-Enterprise"
    return "Unknown"


def security_is_crackable_offline(s):
    return s in ("WPA1-PSK", "WPA2-PSK", "WPA2/WPA3-Transition")

def security_is_enterprise(s):
    return s in ("WPA1-Enterprise", "WPA2-Enterprise", "WPA3-Enterprise")

def security_is_sae(s):
    return s in ("WPA3-SAE", "WPA3-SAE-EXT")


# ============================================================================
# Beacon / AssocReq
# ============================================================================

def parse_beacon_ies(pkt, fixed_len=12):
    out = {
        "ssid": None, "rsn": None, "wpa1": None, "channel": None,
        "security": "Open", "rsn_caps": 0, "pmkid": None, "pmkids": [],
        "ext_caps": None, "ext_rsn_caps": None, "h2e_support": False,
    }
    ie_off = 24 + fixed_len
    if len(pkt) < ie_off:
        return out
    to = ie_off
    while to + 2 <= len(pkt):
        tag_num, tag_len = pkt[to], pkt[to + 1]
        if to + 2 + tag_len > len(pkt):
            break
        tag_val = pkt[to + 2:to + 2 + tag_len]
        if tag_num == 0:
            out["ssid"] = safe_decode(tag_val)
        elif tag_num == 3 and len(tag_val) >= 1:
            out["channel"] = tag_val[0]
        elif tag_num == 48:
            out["rsn"] = parse_rsn_ie(tag_val)
        elif tag_num == 221 and len(tag_val) >= 4:
            if tag_val[0:3] == b"\x00\x50\xf2" and tag_val[3] == 0x01:
                out["wpa1"] = parse_wpa1_ie(tag_val)
        elif tag_num == 127 and len(tag_val) >= 1:
            out["ext_caps"] = tag_val.hex()
        to += 2 + tag_len

    if out["rsn"] is not None:
        out["rsn_caps"] = out["rsn"].get("rsn_caps", 0)
        out["pmkid"] = out["rsn"].get("pmkid")
        out["pmkids"] = out["rsn"].get("pmkids", [])
        out["ext_rsn_caps"] = out["rsn"].get("ext_rsn_caps")
        out["security"] = classify_security(out["rsn"], out.get("wpa1"))
        if out["ext_rsn_caps"] is not None:
            out["h2e_support"] = bool(out["ext_rsn_caps"] & 0x0002)
    elif out.get("wpa1") is not None:
        out["security"] = classify_security(None, out["wpa1"])
    return out


def parse_assoc_request(pkt, h):
    if h["ftype"] != FT_MGMT or h["subtype"] not in (ST_ASSOC_REQ, ST_REASSOC_REQ):
        return None
    fixed_len = 4 if h["subtype"] == ST_ASSOC_REQ else 10
    ie_off = 24 + fixed_len
    if len(pkt) < ie_off:
        return None
    out = {
        "bssid": mac_hex(h["addr1"]), "sta": mac_hex(h["addr2"]),
        "ssid": None, "rsn": None, "wpa1": None, "security": "Open",
        "pmkid": None, "pmkids": [],
    }
    to = ie_off
    while to + 2 <= len(pkt):
        tag_num, tag_len = pkt[to], pkt[to + 1]
        if to + 2 + tag_len > len(pkt):
            break
        tag_val = pkt[to + 2:to + 2 + tag_len]
        if tag_num == 0:
            out["ssid"] = safe_decode(tag_val)
        elif tag_num == 48:
            out["rsn"] = parse_rsn_ie(tag_val)
        elif tag_num == 221 and len(tag_val) >= 4:
            if tag_val[0:3] == b"\x00\x50\xf2" and tag_val[3] == 0x01:
                out["wpa1"] = parse_wpa1_ie(tag_val)
        to += 2 + tag_len
    if out["rsn"] is not None:
        out["pmkid"] = out["rsn"].get("pmkid")
        out["pmkids"] = out["rsn"].get("pmkids", [])
        out["security"] = classify_security(out["rsn"], out.get("wpa1"))
    elif out.get("wpa1") is not None:
        out["security"] = classify_security(None, out["wpa1"])
    return out


# ============================================================================
# EAPOL
# ============================================================================

def eapol_message_number(key_info):
    install = (key_info >> 6) & 1
    ack     = (key_info >> 7) & 1
    mic     = (key_info >> 8) & 1
    secure  = (key_info >> 9) & 1
    if not mic and ack and not install: return 1
    if mic and not secure and not install and not ack: return 2
    if mic and secure and install and ack: return 3
    if mic and secure and not install and not ack: return 4
    if mic and secure and ack and not install: return 3
    return None


def extract_pmkid_kde(key_data):
    pos = 0
    while pos + 2 <= len(key_data):
        elem_id = key_data[pos]
        elem_len = key_data[pos + 1]
        if pos + 2 + elem_len > len(key_data): return None
        elem = key_data[pos + 2:pos + 2 + elem_len]
        if elem_id == 0xDD and len(elem) >= 20:
            if elem[0:3] == b"\x00\x0f\xac" and elem[3] == 0x04:
                return elem[4:20]
        pos += 2 + elem_len
    return None


def parse_eapol(eapol):
    if len(eapol) < 99: return None
    if eapol[1] != EAPOL_KEY: return None
    descriptor = eapol[4]
    key_info = struct.unpack_from(">H", eapol, 5)[0]
    key_len = struct.unpack_from(">H", eapol, 7)[0]
    replay = struct.unpack_from(">Q", eapol, 9)[0]
    nonce = eapol[17:49]
    mic = eapol[81:97]
    key_data_len = struct.unpack_from(">H", eapol, 97)[0]
    msg = eapol_message_number(key_info)
    pmkid = None
    if key_data_len > 0 and len(eapol) >= 99 + key_data_len:
        pmkid = extract_pmkid_kde(eapol[99:99 + key_data_len])
    return {
        "version": eapol[0], "descriptor": descriptor, "key_info": key_info,
        "key_len": key_len, "replay": replay, "nonce": nonce, "mic": mic,
        "key_data_len": key_data_len, "msg": msg, "raw": eapol, "pmkid": pmkid,
    }


def detect_enterprise_eap(eapol):
    if len(eapol) < 4: return None
    eapol_type = eapol[1]
    if eapol_type not in (EAPOL_EAP_PACKET, EAPOL_START, EAPOL_LOGOFF):
        return None
    result = {"eapol_type": eapol_type, "eap_code": None, "eap_type": None}
    if eapol_type == EAPOL_EAP_PACKET and len(eapol) >= 5:
        result["eap_code"] = eapol[4]
        if eapol[4] in (1, 2) and len(eapol) >= 9:
            result["eap_type"] = eapol[8]
    return result


# ============================================================================
# SAE
# ============================================================================

def parse_sae_commit(pkt, h):
    if h["ftype"] != FT_MGMT or h["subtype"] != ST_AUTH: return None
    if len(pkt) < 30: return None
    auth_algo = struct.unpack_from("<H", pkt, 24)[0]
    if auth_algo != SAE_AUTH_ALGO: return None
    auth_seq = struct.unpack_from("<H", pkt, 26)[0]
    status = struct.unpack_from("<H", pkt, 28)[0]
    bssid_hex = mac_hex(h["addr3"])
    if h["addr1"] == h["addr3"]:
        sta_hex = mac_hex(h["addr2"]); direction = "sta->ap"
    else:
        sta_hex = mac_hex(h["addr1"]); direction = "ap->sta"
    result = {
        "bssid": bssid_hex, "sta": sta_hex, "seq": auth_seq,
        "status": status, "direction": direction, "group": None,
        "scalar": None, "element": None, "variant": "unknown",
        "h2e_support": False,
    }
    if status == SAE_STATUS_SAE_HASH_TO_ELEMENT:
        result["h2e_support"] = True
        result["variant"] = "H2E"
    elif status == SAE_STATUS_SUCCESS:
        result["variant"] = "HnP"
    body_off = 30
    if auth_seq == 1 and len(pkt) >= body_off + 2:
        group = struct.unpack_from("<H", pkt, body_off)[0]
        result["group"] = group
        body_off += 2
        sizes = {19: (32, 64), 20: (48, 96), 21: (66, 132)}
        if group in sizes:
            sc_size, el_size = sizes[group]
            if len(pkt) >= body_off + sc_size:
                result["scalar"] = pkt[body_off:body_off + sc_size]
                body_off += sc_size
            if len(pkt) >= body_off + el_size:
                result["element"] = pkt[body_off:body_off + el_size]
    return result


def parse_sae_confirm(pkt, h):
    if h["ftype"] != FT_MGMT or h["subtype"] != ST_AUTH: return None
    if len(pkt) < 30: return None
    auth_algo = struct.unpack_from("<H", pkt, 24)[0]
    if auth_algo != SAE_AUTH_ALGO: return None
    auth_seq = struct.unpack_from("<H", pkt, 26)[0]
    if auth_seq != 2: return None
    status = struct.unpack_from("<H", pkt, 28)[0]
    bssid_hex = mac_hex(h["addr3"])
    if h["addr1"] == h["addr3"]:
        sta_hex = mac_hex(h["addr2"]); direction = "sta->ap"
    else:
        sta_hex = mac_hex(h["addr1"]); direction = "ap->sta"
    confirm_hash = None
    if len(pkt) >= 32 + 32:
        confirm_hash = pkt[32:32 + 32]
    return {
        "bssid": bssid_hex, "sta": sta_hex, "seq": auth_seq,
        "status": status, "direction": direction,
        "confirm_hash": confirm_hash,
    }


# ============================================================================
# Handshake groups
# ============================================================================

class SAEHandshakeGroup:
    __slots__ = ("bssid", "sta", "commits", "confirms", "group", "variant",
                 "h2e_support", "channel", "band")
    def __init__(self, bssid, sta):
        self.bssid = bssid; self.sta = sta
        self.commits = []; self.confirms = []
        self.group = None; self.variant = None; self.h2e_support = False
        self.channel = None; self.band = None

    def add_commit(self, info):
        self.commits.append(info)
        if info.get("group"): self.group = info["group"]
        if info.get("variant") and info["variant"] != "unknown":
            self.variant = info["variant"]
        if info.get("h2e_support"): self.h2e_support = True

    def add_confirm(self, info):
        self.confirms.append(info)

    def is_complete(self):
        return len(self.commits) >= 1 and len(self.confirms) >= 1

    def has_both_directions(self):
        d = {c["direction"] for c in self.commits}
        return "sta->ap" in d and "ap->sta" in d


class HandshakeGroup:
    __slots__ = ("bssid", "sta", "msgs", "pmkid", "channel_ap", "channel_sta",
                 "band_ap", "band_sta")
    def __init__(self, bssid, sta):
        self.bssid = bssid; self.sta = sta
        self.msgs = {}; self.pmkid = None
        self.channel_ap = None; self.channel_sta = None
        self.band_ap = None; self.band_sta = None

    def add(self, msg_num, info):
        if msg_num not in self.msgs:
            self.msgs[msg_num] = info
        elif info["replay"] >= self.msgs[msg_num]["replay"]:
            self.msgs[msg_num] = info

    def best_pair(self):
        if 1 in self.msgs and 2 in self.msgs:
            return self.msgs[1], self.msgs[2], "00"
        if 2 in self.msgs and 3 in self.msgs:
            return self.msgs[2], self.msgs[3], "02"
        if 1 in self.msgs and 4 in self.msgs:
            return self.msgs[1], self.msgs[4], "01"
        return None, None, None

    def validate(self):
        m1, m2, mp = self.best_pair()
        if m1 is None or m2 is None:
            return False, "missing usable message pair"
        if m1["nonce"] == b"\x00" * 32:
            return False, "M1 ANonce is zero"
        if m2["nonce"] == b"\x00" * 32:
            return False, "M2 SNonce is zero"
        if m1["nonce"] == m2["nonce"]:
            return False, "M1 ANonce equals M2 SNonce"
        if (m1["key_len"] != 0 and m2["key_len"] != 0
                and m1["key_len"] != m2["key_len"]):
            return False, "key_len mismatch"
        if m1["descriptor"] != m2["descriptor"]:
            return False, "descriptor mismatch"
        if mp == "00" and m2["replay"] != m1["replay"]:
            return False, f"replay mismatch M1={m1['replay']} M2={m2['replay']}"
        return True, "ok"


# ============================================================================
# Hash builders
# ============================================================================

def build_22000_eapol(group, ssid):
    ok_v, err_v = group.validate()
    if not ok_v: return None, err_v
    m1, m2, mp = group.best_pair()
    if m2["descriptor"] not in (2, 254):
        return None, f"unsupported descriptor {m2['descriptor']}"
    eapol2 = bytearray(m2["raw"])
    if len(eapol2) < 97: return None, "M2 too short"
    eapol2[81:97] = b"\x00" * 16
    eapol2 = bytes(eapol2)
    if ssid is None: return None, "SSID unknown"
    ssid_hex = ssid.encode("utf-8", "replace").hex()
    return (
        f"WPA*02*{m2['mic'].hex()}*{group.bssid}*{group.sta}*{ssid_hex}*"
        f"{m1['nonce'].hex()}*{eapol2.hex()}*{mp}"
    ), None


def build_22000_pmkid(bssid_hex, sta_hex, ssid, pmkid):
    if ssid is None: return None, "SSID unknown"
    if pmkid is None or len(pmkid) != 16: return None, "invalid PMKID"
    ssid_hex = ssid.encode("utf-8", "replace").hex()
    sta = sta_hex if sta_hex and len(sta_hex) == 12 else "0" * 12
    return f"WPA*01*{pmkid.hex()}*{bssid_hex}*{sta}*{ssid_hex}***", None


def build_16800_pmkid(bssid_hex, sta_hex, ssid, pmkid):
    """hashcat -m 16800 format: PMKID*AP_MAC*STA_MAC*ESSID(hex)."""
    if ssid is None or pmkid is None or len(pmkid) != 16:
        return None, "missing SSID/PMKID"
    ssid_hex = ssid.encode("utf-8", "replace").hex()
    sta = sta_hex if sta_hex and len(sta_hex) == 12 else "0" * 12
    return f"{pmkid.hex()}*{bssid_hex}*{sta}*{ssid_hex}", None


def build_sae_hash(group, ssid, bssid_hex, sta_hex):
    if ssid is None: return None, "SSID unknown"
    if not group.is_complete():
        return None, "incomplete SAE handshake"
    sta_commit = None
    for c in group.commits:
        if c["direction"] == "sta->ap":
            sta_commit = c; break
    if sta_commit is None:
        return None, "no STA->AP Commit"
    sta_confirm = None
    for cf in group.confirms:
        if cf["direction"] == "sta->ap":
            sta_confirm = cf; break
    if sta_confirm is None and group.confirms:
        sta_confirm = group.confirms[0]

    ssid_hex = ssid.encode("utf-8", "replace").hex()
    group_num = group.group or 19
    scalar_hex = sta_commit.get("scalar", b"").hex() if sta_commit.get("scalar") else ""
    element_hex = sta_commit.get("element", b"").hex() if sta_commit.get("element") else ""
    confirm_hex = (sta_confirm.get("confirm_hash", b"").hex()
                   if sta_confirm and sta_confirm.get("confirm_hash") else "")
    line = (
        f"WPA*03*{scalar_hex}*{element_hex}*{group_num}*{confirm_hex}*"
        f"{bssid_hex}*{sta_hex}*{ssid_hex}"
    )
    return line, None


# ============================================================================
# WPA2-PSK key derivation & CCMP decryption (v4.0.0)
#
# Implements IEEE 802.11-2016 §12.7 (4-way handshake key derivation) and
# §12.5.3 (CCMP). Only the non-SHA256 PSK AKM (AKM suite 2 — the common
# WPA2-Personal case) is supported for PTK derivation; SAE/802.1X and the
# *-SHA256 AKM variants are intentionally out of scope for this pass.
# TKIP decryption is NOT implemented (CCMP/AES only) — flagged clearly at
# runtime if a TKIP network is targeted.
# ============================================================================

def pbkdf2_pmk(passphrase, ssid):
    """PMK = PBKDF2-HMAC-SHA1(passphrase, ssid, 4096, 256 bits)."""
    return hashlib.pbkdf2_hmac("sha1", passphrase.encode("utf-8"),
                               ssid.encode("utf-8"), 4096, dklen=32)


def prf_sha1(key, label, data, bits):
    """IEEE 802.11 PRF-n: iterative HMAC-SHA1 KDF used pre-SHA256 AKMs."""
    n = (bits + 159) // 160
    out = b""
    for i in range(n):
        out += hmac.new(key, label + b"\x00" + data + bytes([i]),
                        hashlib.sha1).digest()
    return out[:bits // 8]


def derive_ptk_sha1(pmk, aa, spa, anonce, snonce, bits=384):
    """Key Descriptor Version 2 (the common WPA2-Personal case): PTK =
    PRF-384(PMK, 'Pairwise key expansion', min/max(AA,SPA) ||
    min/max(ANonce,SNonce)). Returns 48 bytes for CCMP: KCK|KEK|TK."""
    lo_mac, hi_mac = (aa, spa) if aa < spa else (spa, aa)
    lo_nonce, hi_nonce = (anonce, snonce) if anonce < snonce else (snonce, anonce)
    data = lo_mac + hi_mac + lo_nonce + hi_nonce
    return prf_sha1(pmk, b"Pairwise key expansion", data, bits)


def kdf_sha256(key, label, context, length_bits):
    """IEEE 802.11-2016 12.7.1.6.2 KDF-Hash-Length, SHA-256 flavor (the
    NIST SP800-108 counter-mode construction): used for Key Descriptor
    Version 3 (AKM 00-0F-AC:5 802.1X-SHA256 / 00-0F-AC:6 PSK-SHA256)."""
    result = b""
    i = 1
    length_bytes = (length_bits + 7) // 8
    while len(result) < length_bytes:
        result += hmac.new(
            key,
            struct.pack("<H", i) + label + context + struct.pack("<H", length_bits),
            hashlib.sha256,
        ).digest()
        i += 1
    return result[:length_bytes]


def derive_ptk_sha256(pmk, aa, spa, anonce, snonce, bits=384):
    """Key Descriptor Version 3 (PSK-SHA256 / 802.1X-SHA256): PTK =
    KDF-SHA256(PMK, 'Pairwise key expansion', min/max(AA,SPA) ||
    min/max(ANonce,SNonce), 384)."""
    lo_mac, hi_mac = (aa, spa) if aa < spa else (spa, aa)
    lo_nonce, hi_nonce = (anonce, snonce) if anonce < snonce else (snonce, anonce)
    context = lo_mac + hi_mac + lo_nonce + hi_nonce
    return kdf_sha256(pmk, b"Pairwise key expansion", context, bits)


def eapol_mic_hmac_sha1(kck, eapol_frame_zero_mic):
    """MIC for Key Descriptor Version 2 (HMAC-SHA1) key frames: first 16
    bytes of HMAC-SHA1(KCK, frame-with-MIC-field-zeroed)."""
    return hmac.new(kck, eapol_frame_zero_mic, hashlib.sha1).digest()[:16]


def eapol_mic_aes_cmac(kck, eapol_frame_zero_mic):
    """MIC for Key Descriptor Version 3 (AES-128-CMAC) key frames, used
    with the *-SHA256 AKMs. Full 128-bit CMAC output, no truncation."""
    if not CRYPTO_AVAILABLE:
        return None
    c = CMAC(algorithms.AES(kck))
    c.update(eapol_frame_zero_mic)
    return c.finalize()


def verify_password_against_group(password, ssid, bssid_hex, sta_hex, group):
    """Derive PTK from a candidate password and check it against the
    captured M1/M2 (or M2/M3...) MIC. Auto-detects Key Descriptor Version
    (2 = HMAC-SHA1/PRF-384, 3 = AES-128-CMAC/KDF-SHA256, i.e. the
    *-SHA256 AKMs) from the captured frame itself. Returns
    (ok, ptk_or_None, reason)."""
    m1, m2, mp = group.best_pair()
    if m1 is None:
        return False, None, "no usable EAPOL message pair in capture"
    if m2["descriptor"] not in (2, 254):
        return False, None, f"unsupported EAPOL descriptor {m2['descriptor']}"
    pmk = pbkdf2_pmk(password, ssid)
    aa = bytes.fromhex(bssid_hex)
    spa = bytes.fromhex(sta_hex)

    # Prefer the direct M1(ANonce)/M2(SNonce) pair when available — it's
    # always present whenever any EAPOL was captured at all.
    if 1 in group.msgs and 2 in group.msgs:
        anonce = group.msgs[1]["nonce"]
        snonce = group.msgs[2]["nonce"]
        mic_msg = group.msgs[2]
    elif 2 in group.msgs and 3 in group.msgs:
        anonce = group.msgs[3]["nonce"]
        snonce = group.msgs[2]["nonce"]
        mic_msg = group.msgs[3]
    else:
        return False, None, "need M1+M2 or M2+M3 to verify a password"

    key_desc_version = mic_msg["key_info"] & 0x7
    if key_desc_version == 1:
        return False, None, ("Key Descriptor Version 1 (TKIP/RC4+MD5, "
                             "WPA1) is not implemented")
    if key_desc_version == 3:
        if not CRYPTO_AVAILABLE:
            return False, None, "the 'cryptography' package is required"
        ptk = derive_ptk_sha256(pmk, aa, spa, anonce, snonce, bits=384)
    else:
        ptk = derive_ptk_sha1(pmk, aa, spa, anonce, snonce, bits=384)

    kck, kek, tk = ptk[0:16], ptk[16:32], ptk[32:48]
    frame = bytearray(mic_msg["raw"])
    if len(frame) < 97:
        return False, None, "captured EAPOL frame too short"
    frame[81:97] = b"\x00" * 16
    if key_desc_version == 3:
        calc_mic = eapol_mic_aes_cmac(kck, bytes(frame))
    else:
        calc_mic = eapol_mic_hmac_sha1(kck, bytes(frame))
    if calc_mic != mic_msg["mic"]:
        return False, None, "MIC mismatch — wrong password"
    return True, {"kck": kck, "kek": kek, "tk": tk, "pmk": pmk,
                  "key_desc_version": key_desc_version}, "ok"


def unwrap_gtk_from_m3(key_data, kek):
    """Best-effort GTK extraction from EAPOL-Key message 3's encrypted Key
    Data field (GTK KDE, RFC3394 AES key-wrap — Key Descriptor Version 2,
    the common WPA2-PSK/CCMP case). Returns raw GTK bytes or None."""
    if not CRYPTO_AVAILABLE or len(key_data) < 16 or len(key_data) % 8 != 0:
        return None
    try:
        plain = aes_key_unwrap(kek, bytes(key_data))
    except Exception:
        return None
    # Plain is a sequence of KDEs: type(0xDD) len OUI(3) datatype(1) ...
    pos = 0
    while pos + 2 <= len(plain):
        elem_id, elem_len = plain[pos], plain[pos + 1]
        if pos + 2 + elem_len > len(plain):
            break
        elem = plain[pos + 2:pos + 2 + elem_len]
        if elem_id == 0xDD and len(elem) >= 6 and elem[0:3] == b"\x00\x0f\xac" \
                and elem[3] == 0x01:
            # GTK KDE: OUI(3) type(1)=1 Tx/KeyID(1) Reserved(1) GTK(n)
            return elem[6:]
        pos += 2 + elem_len
    return None


def ccmp_parse_header(pkt, offset):
    """CCMP header is 8 bytes: PN0 PN1 Rsvd (ExtIV|KeyID) PN2 PN3 PN4 PN5."""
    if len(pkt) < offset + 8:
        return None
    h = pkt[offset:offset + 8]
    pn0, pn1 = h[0], h[1]
    keyid_byte = h[3]
    key_id = (keyid_byte >> 6) & 0x3
    ext_iv = bool(keyid_byte & 0x20)
    pn2, pn3, pn4, pn5 = h[4], h[5], h[6], h[7]
    pn = bytes([pn5, pn4, pn3, pn2, pn1, pn0])  # PN5..PN0, MSB first
    return {"key_id": key_id, "ext_iv": ext_iv, "pn": pn, "hdr_len": 8}


def ccmp_build_nonce(a2, pn):
    """Nonce = Priority(1, 0 for non-QoS) || A2 (6) || PN (6, MSB first)."""
    return b"\x00" + a2 + pn


def ccmp_build_aad(pkt, h):
    """AAD per 802.11-2016 Table 12-5: FC (masked) || A1 || A2 || A3 ||
    SC (seq masked, frag kept) || [A4] || [QoS masked to TID only]."""
    fc = h["fc"]
    # Mask: retry(11), pwrmgmt(12), moredata(13) -> 0; subtype bits 4-7 kept;
    # also mask "order" only for non-QoS per spec table (kept simple: keep
    # protected(14) and order(15) as-is, matching common implementations).
    fc_masked = fc & ~((1 << 11) | (1 << 12) | (1 << 13))
    aad = struct.pack("<H", fc_masked)
    aad += bytes(h["addr1"]) + bytes(h["addr2"]) + bytes(h["addr3"])
    seq_masked = h["seq"] & 0x000F  # keep fragment number, zero seq number
    aad += struct.pack("<H", seq_masked)
    if h.get("hdr_len", 24) == 30:
        a4_off = 24
        aad += bytes(pkt[a4_off:a4_off + 6])
    if h["ftype"] == FT_DATA and (h["subtype"] & 0x8):
        qos_off = h["hdr_len"] - 2 - (4 if h.get("order") and h["hdr_len"] == 30
                                      else 0)
        # QoS Control: only TID (low byte, low 4 bits) is protected by AAD,
        # the rest is masked to 0 (and for non-AMSDU bit 7 masked too).
        if 0 <= qos_off <= len(pkt) - 2:
            tid = pkt[qos_off] & 0x0F
            aad += bytes([tid, 0x00])
    return bytes(aad)


def ccmp_decrypt_data(pkt, h, key):
    """Decrypt one CCMP-protected 802.11 Data frame body. Returns the
    decrypted LLC/payload bytes, or None if decryption/auth fails."""
    if not CRYPTO_AVAILABLE:
        return None
    body = pkt[h["hdr_len"]:]
    ch = ccmp_parse_header(body, 0)
    if ch is None:
        return None
    ciphertext = body[8:]
    if len(ciphertext) < 8:
        return None
    nonce = ccmp_build_nonce(bytes(h["addr2"]), ch["pn"])
    aad = ccmp_build_aad(pkt, h)
    try:
        aesccm = AESCCM(key, tag_length=8)
        plain = aesccm.decrypt(nonce, ciphertext, aad)
    except Exception:
        return None
    return plain


def dot11_to_ethernet(h, llc_payload):
    """Convert a decrypted 802.11 Data frame (addr1/2/3[/4] + LLC/SNAP
    payload) into an Ethernet II frame, the way airdecap-ng does it."""
    if h["to_ds"] and not h["from_ds"]:
        dst, src = bytes(h["addr3"]), bytes(h["addr2"])
    elif h["from_ds"] and not h["to_ds"]:
        dst, src = bytes(h["addr1"]), bytes(h["addr3"])
    else:
        dst, src = bytes(h["addr1"]), bytes(h["addr2"])
    if len(llc_payload) < 8 or llc_payload[0:3] != b"\xaa\xaa\x03":
        return None
    ethertype = llc_payload[6:8]
    payload = llc_payload[8:]
    return dst + src + ethertype + payload


# ============================================================================
# Worker
# ============================================================================

def process_batch(packets):
    results = {
        "ssids": {}, "groups": {}, "sae_groups": {},
        "enterprise_frames": defaultdict(list),
        "assoc_clients": defaultdict(set),
        "beacon_pmkids": {},
        "packet_count": 0, "linktypes_seen": set(),
        "frame_stats": defaultdict(int),
    }
    fragbuf = FragBuffer()
    for linktype, ts, pkt in packets:
        results["packet_count"] += 1
        results["linktypes_seen"].add(linktype)
        rt = parse_radiotap(pkt)
        pkt2 = rt["body"]
        chan_hint = rt["chan_freq"]
        band_hint = rt["band"]
        h = parse_80211_header(pkt2)
        if h is None:
            results["frame_stats"]["unparsable"] += 1
            continue
        fs = results["frame_stats"]
        fs["mgmt" if h["ftype"] == FT_MGMT else
           "ctrl" if h["ftype"] == FT_CTRL else "data"] += 1
        if h["ftype"] == FT_DATA:
            if h["protected"]:
                fs["data_encrypted"] += 1
            else:
                fs["data_plaintext"] += 1

        # Beacon / ProbeResp
        if h["ftype"] == FT_MGMT and h["subtype"] in (ST_BEACON, ST_PROBE_RESP):
            info = parse_beacon_ies(pkt2, fixed_len=12)
            bssid_hex = mac_hex(h["addr3"])
            if info["channel"] is None and chan_hint is not None:
                info["channel"] = freq_to_channel(chan_hint, band_hint)
            info["band"] = band_hint
            if bssid_hex not in results["ssids"]:
                results["ssids"][bssid_hex] = info
            else:
                ex = results["ssids"][bssid_hex]
                if ex.get("ssid") is None and info.get("ssid"):
                    ex["ssid"] = info["ssid"]
                if ex.get("rsn") is None and info.get("rsn"):
                    ex["rsn"] = info["rsn"]
                    ex["security"] = info["security"]
                    ex["h2e_support"] = info.get("h2e_support", False)
            if info.get("pmkids") and info.get("ssid"):
                if bssid_hex not in results["beacon_pmkids"]:
                    results["beacon_pmkids"][bssid_hex] = (info["ssid"],
                                                           info["pmkids"][0])
            continue

        # Assoc/Reassoc Req
        if h["ftype"] == FT_MGMT and h["subtype"] in (ST_ASSOC_REQ, ST_REASSOC_REQ):
            assoc = parse_assoc_request(pkt2, h)
            if assoc:
                results["assoc_clients"][assoc["bssid"]].add(assoc["sta"])
                ex = results["ssids"].get(assoc["bssid"])
                merged = {
                    "ssid": assoc["ssid"] or (ex["ssid"] if ex else None),
                    "rsn": assoc["rsn"] or (ex["rsn"] if ex else None),
                    "wpa1": assoc.get("wpa1") or (ex.get("wpa1") if ex else None),
                    "channel": ex["channel"] if ex else None,
                    "band": ex.get("band") if ex else band_hint,
                    "security": assoc["security"],
                    "h2e_support": ex.get("h2e_support", False) if ex else False,
                }
                results["ssids"][assoc["bssid"]] = merged
            continue

        # SAE Auth
        if h["ftype"] == FT_MGMT and h["subtype"] == ST_AUTH:
            sae = parse_sae_commit(pkt2, h)
            if sae:
                key = (sae["bssid"], sae["sta"])
                if key not in results["sae_groups"]:
                    results["sae_groups"][key] = SAEHandshakeGroup(
                        sae["bssid"], sae["sta"])
                results["sae_groups"][key].add_commit(sae)
                results["sae_groups"][key].channel = chan_hint
                results["sae_groups"][key].band = band_hint
                continue
            confirm = parse_sae_confirm(pkt2, h)
            if confirm:
                key = (confirm["bssid"], confirm["sta"])
                if key not in results["sae_groups"]:
                    results["sae_groups"][key] = SAEHandshakeGroup(
                        confirm["bssid"], confirm["sta"])
                results["sae_groups"][key].add_confirm(confirm)
                continue
            continue

        # Data / EAPOL
        if h["ftype"] == FT_DATA and not h["protected"]:
            body = pkt2[h["hdr_len"]:]
            body = fragbuf.push(h, body)
            if body is None: continue
            if len(body) < 8 or body[0:3] != b"\xaa\xaa\x03": continue
            ethertype = struct.unpack_from(">H", body, 6)[0]
            if ethertype != 0x888E: continue
            eapol = body[8:]
            if h["to_ds"] and not h["from_ds"]:
                bssid, sta = h["addr1"], h["addr2"]
            elif h["from_ds"] and not h["to_ds"]:
                bssid, sta = h["addr2"], h["addr1"]
            else:
                bssid, sta = h["addr3"], h["addr2"]
            bssid_hex = mac_hex(bssid); sta_hex = mac_hex(sta)
            ent = detect_enterprise_eap(eapol)
            if ent is not None:
                results["enterprise_frames"][(bssid_hex, sta_hex)].append(ent)
                continue
            info = parse_eapol(eapol)
            if info is None or info["msg"] is None: continue
            key = (bssid_hex, sta_hex)
            if key not in results["groups"]:
                results["groups"][key] = HandshakeGroup(bssid_hex, sta_hex)
            g = results["groups"][key]
            g.add(info["msg"], info)
            if info["pmkid"] is not None and g.pmkid is None:
                g.pmkid = info["pmkid"]
            if info["msg"] == 1:
                g.channel_ap = chan_hint; g.band_ap = band_hint
            elif info["msg"] == 2:
                g.channel_sta = chan_hint; g.band_sta = band_hint
    return results


def merge_results(all_r):
    merged = {
        "ssids": {}, "groups": {}, "sae_groups": {},
        "enterprise_frames": defaultdict(list),
        "assoc_clients": defaultdict(set),
        "beacon_pmkids": {},
        "packet_count": 0, "linktypes_seen": set(),
        "frame_stats": defaultdict(int),
    }
    for r in all_r:
        merged["packet_count"] += r["packet_count"]
        merged["linktypes_seen"].update(r["linktypes_seen"])
        for k, v in r.get("frame_stats", {}).items():
            merged["frame_stats"][k] += v
        for b, i in r["ssids"].items():
            if b not in merged["ssids"]:
                merged["ssids"][b] = i
            else:
                ex = merged["ssids"][b]
                if ex.get("ssid") is None and i.get("ssid"): ex["ssid"] = i["ssid"]
                if ex.get("rsn") is None and i.get("rsn"):
                    ex["rsn"] = i["rsn"]; ex["security"] = i["security"]
        for k, g in r["groups"].items():
            if k not in merged["groups"]:
                merged["groups"][k] = g
            else:
                for mn, info in g.msgs.items():
                    merged["groups"][k].add(mn, info)
                if g.pmkid and not merged["groups"][k].pmkid:
                    merged["groups"][k].pmkid = g.pmkid
        for k, g in r["sae_groups"].items():
            if k not in merged["sae_groups"]:
                merged["sae_groups"][k] = g
            else:
                for c in g.commits: merged["sae_groups"][k].add_commit(c)
                for c in g.confirms: merged["sae_groups"][k].add_confirm(c)
        for k, f in r["enterprise_frames"].items():
            merged["enterprise_frames"][k].extend(f)
        for b, cl in r["assoc_clients"].items():
            merged["assoc_clients"][b].update(cl)
        for b, p in r["beacon_pmkids"].items():
            if b not in merged["beacon_pmkids"]:
                merged["beacon_pmkids"][b] = p
    return merged


# ============================================================================
# Capture analysis pipeline
# ============================================================================

def analyze_capture(path, threads=0, chunk_size=10000, show_progress=True):
    if threads <= 0:
        threads = min(8, os.cpu_count() or 4)
    reader = open_reader(path)
    all_results = []
    chunk = []
    progress = ProgressBar(0, prefix="Parsing",
                           enable=show_progress and sys.stderr.isatty())
    # We don't know total packets up front for streaming; estimate by file size
    try:
        file_size = os.path.getsize(path)
        est_pkts = max(file_size // 200, 1000)
    except Exception:
        est_pkts = 1000
    progress.total = est_pkts

    t0 = time.time()
    try:
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = []
            for linktype, ts, pkt in reader:
                chunk.append((linktype, ts, pkt))
                if len(chunk) >= chunk_size:
                    futures.append(ex.submit(process_batch, chunk))
                    chunk = []
                    progress.update(chunk_size)
            if chunk:
                futures.append(ex.submit(process_batch, chunk))
                progress.update(len(chunk))
            for f in as_completed(futures):
                all_results.append(f.result())
    finally:
        reader.close()
        progress.close()
    elapsed = time.time() - t0
    results = merge_results(all_results)
    results["elapsed"] = elapsed
    results["file_size"] = file_size
    return results


# ============================================================================
# Full packet report (-a --stats/--packets/--payloads/--full)
#
# Separate, single-threaded pass (kept apart from the fast multithreaded
# process_batch() used for the default handshake-hunting analysis) so a
# user who just wants "how many packets / which were encrypted" doesn't
# pay for per-packet bookkeeping on every run. Memory-bounded: full
# per-packet records are capped at PACKET_RECORD_CAP; past that only the
# running totals keep going.
# ============================================================================

PACKET_RECORD_CAP = 20000
PAYLOAD_DUMP_BYTES = 48
TERMINAL_PRINT_CAP = 60

FTYPE_NAMES = {FT_MGMT: "mgmt", FT_CTRL: "ctrl", FT_DATA: "data"}
MGMT_SUBTYPE_NAMES = {
    ST_ASSOC_REQ: "AssocReq", ST_ASSOC_RESP: "AssocResp",
    ST_REASSOC_REQ: "ReassocReq", ST_REASSOC_RSP: "ReassocResp",
    ST_PROBE_REQ: "ProbeReq", ST_PROBE_RESP: "ProbeResp",
    ST_BEACON: "Beacon", ST_ATIM: "ATIM", ST_DISASSOC: "Disassoc",
    ST_AUTH: "Auth", ST_DEAUTH: "Deauth",
}
DATA_SUBTYPE_NAMES = {
    0: "Data", 1: "Data+CFAck", 2: "Data+CFPoll", 3: "Data+CFAck+CFPoll",
    4: "Null", 5: "CFAck", 6: "CFPoll", 7: "CFAck+CFPoll",
    8: "QoSData", 9: "QoSData+CFAck", 10: "QoSData+CFPoll",
    11: "QoSData+CFAck+CFPoll", 12: "QoSNull", 14: "QoSCFPoll",
    15: "QoSCFAck+CFPoll",
}
CTRL_SUBTYPE_NAMES = {
    7: "ControlWrapper", 8: "BlockAckReq", 9: "BlockAck", 10: "PSPoll",
    11: "RTS", 12: "CTS", 13: "ACK", 14: "CFEnd", 15: "CFEnd+CFAck",
}


def subtype_name(ftype, subtype):
    table = (MGMT_SUBTYPE_NAMES if ftype == FT_MGMT else
             DATA_SUBTYPE_NAMES if ftype == FT_DATA else
             CTRL_SUBTYPE_NAMES if ftype == FT_CTRL else {})
    return table.get(subtype, f"subtype{subtype}")

IP_PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}


def _hex_preview(b, n=PAYLOAD_DUMP_BYTES):
    chunk = b[:n]
    hexs = chunk.hex()
    ascii_s = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
    suffix = "..." if len(b) > n else ""
    return hexs + suffix, ascii_s + suffix


def summarize_plaintext_llc(ethertype, payload):
    """Best-effort protocol identification for a decrypted/plaintext LLC
    payload. Returns a short human string."""
    if ethertype == 0x0806:
        return "ARP"
    if ethertype == 0x888E:
        return "EAPOL"
    if ethertype == 0x86DD:
        return "IPv6"
    if ethertype == 0x0800:
        if len(payload) < 20:
            return "IPv4 (truncated)"
        ver_ihl = payload[0]
        ihl = (ver_ihl & 0x0F) * 4
        if len(payload) < ihl:
            return "IPv4 (truncated)"
        proto = payload[9]
        src = ".".join(str(b) for b in payload[12:16])
        dst = ".".join(str(b) for b in payload[16:20])
        proto_name = IP_PROTO_NAMES.get(proto, f"proto {proto}")
        l4 = payload[ihl:]
        if proto == 17 and len(l4) >= 4:  # UDP
            sport, dport = struct.unpack_from(">HH", l4, 0)
            if 67 in (sport, dport) or 68 in (sport, dport):
                return f"DHCP {src} -> {dst}"
            if 53 in (sport, dport):
                return f"DNS {src} -> {dst}"
            return f"UDP {src}:{sport} -> {dst}:{dport}"
        if proto == 6 and len(l4) >= 4:  # TCP
            sport, dport = struct.unpack_from(">HH", l4, 0)
            return f"TCP {src}:{sport} -> {dst}:{dport}"
        return f"{proto_name} {src} -> {dst}"
    return f"ethertype 0x{ethertype:04x}"


def full_packet_scan(path, show_progress=True):
    reader = open_reader(path)
    out = {
        "total": 0, "mgmt": 0, "ctrl": 0, "data": 0,
        "data_encrypted": 0, "data_plaintext": 0, "unparsable": 0,
        "by_subtype": defaultdict(int), "records": [],
        "truncated": False, "elapsed": 0.0,
    }
    progress = ProgressBar(0, prefix="Scanning",
                           enable=show_progress and sys.stderr.isatty())
    try:
        file_size = os.path.getsize(path)
        progress.total = max(file_size // 200, 1000)
    except Exception:
        progress.total = 1000
    t0 = time.time()
    try:
        idx = 0
        for linktype, ts, pkt in reader:
            idx += 1
            out["total"] += 1
            progress.update(1)
            rt = parse_radiotap(pkt)
            pkt2 = rt["body"]
            h = parse_80211_header(pkt2)
            if h is None:
                out["unparsable"] += 1
                continue
            ftype_name = FTYPE_NAMES.get(h["ftype"], "?")
            out[ftype_name if ftype_name in ("mgmt", "ctrl") else "data"] += 1
            sub_name = subtype_name(h["ftype"], h["subtype"])
            out["by_subtype"][f"{ftype_name}/{sub_name}"] += 1

            rec = {
                "idx": idx, "ts": ts, "ftype": ftype_name, "subtype": sub_name,
                "addr1": mac(h["addr1"]), "addr2": mac(h["addr2"]),
                "addr3": mac(h["addr3"]), "len": len(pkt),
                "protected": bool(h["protected"]), "summary": "", "payload_hex": "",
                "payload_ascii": "",
            }
            if h["ftype"] == FT_DATA:
                if h["protected"]:
                    out["data_encrypted"] += 1
                    body = pkt2[h["hdr_len"]:]
                    ch = ccmp_parse_header(body, 0)
                    if ch:
                        rec["summary"] = f"CCMP encrypted (PN={ch['pn'].hex()})"
                        hexp, asciip = _hex_preview(body[8:])
                    else:
                        rec["summary"] = "encrypted (non-CCMP or malformed)"
                        hexp, asciip = _hex_preview(body)
                    rec["payload_hex"], rec["payload_ascii"] = hexp, asciip
                else:
                    out["data_plaintext"] += 1
                    body = pkt2[h["hdr_len"]:]
                    if len(body) >= 8 and body[0:3] == b"\xaa\xaa\x03":
                        ethertype = struct.unpack_from(">H", body, 6)[0]
                        payload = body[8:]
                        rec["summary"] = summarize_plaintext_llc(ethertype, payload)
                        hexp, asciip = _hex_preview(payload)
                        rec["payload_hex"], rec["payload_ascii"] = hexp, asciip
                    else:
                        rec["summary"] = "data (non-LLC/SNAP)"
            elif h["ftype"] == FT_MGMT:
                rec["summary"] = sub_name
            else:
                rec["summary"] = sub_name

            if len(out["records"]) < PACKET_RECORD_CAP:
                out["records"].append(rec)
            else:
                out["truncated"] = True
    finally:
        reader.close()
        progress.close()
    out["elapsed"] = time.time() - t0
    return out


def report_packet_stats(full):
    print_separator("Full Packet Stats")
    print(f"  Total packets      : {full['total']}  "
          f"({full['elapsed']:.2f}s)")
    print(f"  Management         : {full['mgmt']}")
    print(f"  Control            : {full['ctrl']}")
    print(f"  Data (encrypted)   : {C.YELLOW}{full['data_encrypted']}{C.RESET}")
    print(f"  Data (plaintext)   : {full['data_plaintext']}")
    if full["unparsable"]:
        print(f"  Unparsable         : {full['unparsable']}")
    if full["by_subtype"]:
        print(f"  {C.DIM}By subtype:{C.RESET}")
        for name, n in sorted(full["by_subtype"].items(), key=lambda kv: -kv[1]):
            print(f"    {name:<14}: {n}")


def report_packet_list(full):
    print_separator(f"Packet List (showing up to {TERMINAL_PRINT_CAP})")
    print(f"  {'#':<6} {'TYPE':<10} {'A2 (src)':<18} {'A1 (dst)':<18} "
          f"{'LEN':<6} SUMMARY")
    for rec in full["records"][:TERMINAL_PRINT_CAP]:
        flag = f"{C.YELLOW}E{C.RESET}" if rec["protected"] else " "
        print(f"  {rec['idx']:<6} {rec['ftype']+'/'+rec['subtype']:<10} "
              f"{rec['addr2']:<18} {rec['addr1']:<18} {rec['len']:<6} "
              f"{flag} {rec['summary']}")
    if len(full["records"]) > TERMINAL_PRINT_CAP:
        info(f"... {len(full['records']) - TERMINAL_PRINT_CAP} more packets "
             f"not shown (use -o report.json/.csv to export all)")
    if full["truncated"]:
        warn(f"packet record cap ({PACKET_RECORD_CAP}) reached — stats above "
             f"are still exact, but the detailed list/export is partial")


def report_packet_payloads(full):
    data_recs = [r for r in full["records"] if r["ftype"] == "data" and r["payload_hex"]]
    print_separator(f"Payload Dump (showing up to {TERMINAL_PRINT_CAP} "
                    f"data frames, first {PAYLOAD_DUMP_BYTES}B each)")
    for rec in data_recs[:TERMINAL_PRINT_CAP]:
        tag = f"{C.YELLOW}[encrypted]{C.RESET}" if rec["protected"] else "[plain]"
        print(f"  #{rec['idx']} {tag} {rec['summary']}")
        print(f"    hex  : {rec['payload_hex']}")
        print(f"    ascii: {rec['payload_ascii']}")
    if len(data_recs) > TERMINAL_PRINT_CAP:
        info(f"... {len(data_recs) - TERMINAL_PRINT_CAP} more data frames "
             f"not shown (use -o report.json to export all)")


def export_report(full, out_path):
    ext = os.path.splitext(out_path)[1].lower()
    recs = full["records"]
    if ext == ".json":
        payload = {k: v for k, v in full.items() if k != "records"}
        payload["by_subtype"] = dict(full["by_subtype"])
        payload["records"] = recs
        with open(out_path, "w") as f:
            json.dump(payload, f, indent=2)
    elif ext == ".csv":
        with open(out_path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["idx", "ts", "ftype", "subtype",
                                              "addr1", "addr2", "addr3", "len",
                                              "protected", "summary",
                                              "payload_hex"])
            w.writeheader()
            for r in recs:
                row = {k: r.get(k) for k in w.fieldnames}
                w.writerow(row)
    else:
        with open(out_path, "w") as f:
            f.write(f"Wiforge packet report — total={full['total']}\n")
            for r in recs:
                f.write(f"#{r['idx']} {r['ftype']}/{r['subtype']} "
                        f"{r['addr2']} -> {r['addr1']} len={r['len']} "
                        f"{'ENCRYPTED' if r['protected'] else ''} "
                        f"{r['summary']}\n")


# ============================================================================
# Reporting
# ============================================================================

LINKTYPE_NAMES = {
    0: "DLT_NULL / raw",
    105: "IEEE 802.11 raw",
    127: "IEEE 802.11 + Radiotap",
    163: "IEEE 802.11 + AVS",
    119: "IEEE 802.11 + Prism",
}


def linktype_name(lt):
    return LINKTYPE_NAMES.get(lt, f"unknown ({lt})")


def print_separator(title=None):
    line = "─" * 66
    if title:
        pad = max(0, 66 - len(title) - 4)
        left = pad // 2
        right = pad - left
        print(f"{C.DIM}{'─' * left}{C.RESET} {C.BOLD}{title}{C.RESET} "
              f"{C.DIM}{'─' * right}{C.RESET}")
    else:
        print(f"{C.DIM}{line}{C.RESET}")


def report_networks(results, show_clients=False, show_pmkid=False,
                    show_channels=False):
    if not results["ssids"]:
        return
    print_separator(f"Networks ({len(results['ssids'])})")
    header = f"  {'SSID':<20} {'BSSID':<18} {'CH':<4} {'SECURITY':<22}"
    if show_clients:
        header += " CLIENTS"
    print(f"{C.BOLD}{header}{C.RESET}")
    print(f"  {'─' * (62 + (8 if show_clients else 0))}")
    for bssid_hex, info in results["ssids"].items():
        ssid = (info.get("ssid") or "?")[:20]
        ch = info.get("channel")
        ch_s = str(ch) if ch is not None else "?"
        sec = info.get("security", "?")
        if info.get("rsn") and info["rsn"].get("pairwise"):
            ciphers = ", ".join(CIPHER_MAP.get(c, c)
                                for c in info["rsn"]["pairwise"])
            sec_disp = f"{sec} ({ciphers})"
        else:
            sec_disp = sec
        sec_disp = sec_disp[:22]
        row = f"  {ssid:<20} {bssid_hex:<18} {ch_s:<4} {sec_disp:<22}"
        if show_clients:
            clients = sorted(results["assoc_clients"].get(bssid_hex, set()))
            row += " " + (", ".join(clients) if clients else "?")
        print(row)
        if show_channels:
            band = info.get("band") or "?"
            print(f"      {C.DIM}band={band}  h2e={info.get('h2e_support', False)}{C.RESET}")
        if show_pmkid and info.get("pmkids"):
            for p in info["pmkids"]:
                print(f"      {C.DIM}PMKID: {p.hex()}{C.RESET}")


def report_sae(results, verbose=False):
    groups = results["sae_groups"]
    if not groups:
        return
    print_separator(f"WPA3-SAE ({len(groups)})")
    complete = 0
    for (bssid_hex, sta_hex), g in groups.items():
        comp = g.is_complete()
        if comp: complete += 1
        status = (f"{C.GREEN}✓ COMPLETE{C.RESET}" if comp
                  else f"{C.YELLOW}✗ INCOMPLETE{C.RESET}")
        variant = g.variant or "unknown"
        print(f"  BSSID={bssid_hex}  STA={sta_hex}")
        print(f"    Status   : {status}")
        print(f"    Variant  : {variant}  Group: {g.group or '?'}")
        print(f"    Commits  : {len(g.commits)}  Confirms: {len(g.confirms)}")
        if verbose:
            for c in g.commits:
                print(f"      {C.DIM}commit {c['direction']} seq={c['seq']} "
                      f"group={c['group']}{C.RESET}")
    print(f"\n  Total: {len(groups)}  Complete: {complete}")


def report_enterprise(results, verbose=False):
    frames = results["enterprise_frames"]
    if not frames:
        return
    eap_names = {
        1: "Identity", 2: "Notification", 3: "Nak", 4: "MD5-Challenge",
        5: "OTP", 6: "GTC", 13: "EAP-TLS", 18: "EAP-SIM",
        21: "EAP-TTLS", 23: "EAP-AKA", 25: "PEAP", 26: "MSCHAPv2",
        43: "EAP-FAST", 50: "EAP-TLS (exp)", 55: "EAP-MSCHAPv2",
    }
    print_separator(f"802.1X Enterprise ({len(frames)})")
    has_mschap = False
    for (bssid_hex, sta_hex), fl in frames.items():
        types = set()
        for f in fl:
            if f.get("eap_type"):
                types.add(f["eap_type"])
                if f["eap_type"] in (26, 55):
                    has_mschap = True
        tstr = ", ".join(f"{t}({eap_names.get(t, '?')})"
                         for t in sorted(types)) or "n/a"
        print(f"  BSSID={bssid_hex}  STA={sta_hex}")
        print(f"    EAP types: {tstr}")
    if has_mschap:
        print(f"\n  {C.YELLOW}MSCHAPv2 detected — crack with "
              f"hashcat -m 5500{C.RESET}")


def report_summary_counts(results):
    eapol_count = sum(1 for g in results["groups"].values()
                      if g.best_pair()[0] is not None)
    pmkid_count = len(results["beacon_pmkids"]) + sum(
        1 for g in results["groups"].values() if g.pmkid)
    sae_count = sum(1 for g in results["sae_groups"].values()
                    if g.is_complete())
    ent_count = len(results["enterprise_frames"])
    print_separator("Handshakes Found")
    print(f"  EAPOL  : {eapol_count}")
    print(f"  PMKID  : {pmkid_count}")
    print(f"  SAE    : {sae_count} (online only)")
    print(f"  EAP    : {ent_count}")


def report_frame_stats(results):
    fs = results.get("frame_stats", {})
    total = results["packet_count"]
    mgmt = fs.get("mgmt", 0)
    ctrl = fs.get("ctrl", 0)
    data_enc = fs.get("data_encrypted", 0)
    data_plain = fs.get("data_plaintext", 0)
    data_total = data_enc + data_plain
    unparsable = fs.get("unparsable", 0)
    print_separator("Packet Breakdown")
    print(f"  Total packets      : {total}")
    print(f"  Management frames  : {mgmt}")
    print(f"  Control frames     : {ctrl}")
    print(f"  Data frames        : {data_total}")
    pct = (data_enc / data_total * 100) if data_total else 0.0
    print(f"    {C.YELLOW}Encrypted{C.RESET}        : {data_enc} "
          f"({pct:.1f}% of data frames)")
    print(f"    Plaintext        : {data_plain}")
    if unparsable:
        print(f"  Unparsable         : {unparsable}")


# ============================================================================
# Hash extraction (writes files)
# ============================================================================

def write_hash_files(results, input_path, output_dir=None, sae_warn=True,
                     formats=None):
    """Write hash files. `formats` restricts which to produce, e.g.
    {"22000", "16800", "sae", "5500"}; None means all. Returns dict of
    {type: (path, count)}."""
    if formats is None:
        formats = {"22000", "16800", "sae", "5500"}
    if output_dir is None:
        output_dir = os.path.dirname(os.path.abspath(input_path)) or "."
    os.makedirs(output_dir, exist_ok=True)
    base = os.path.splitext(os.path.basename(input_path))[0]

    written = {}

    # Collect hashes
    eapol_pmkid_lines = []
    pmkid16800_lines = []
    sae_lines = []
    mschap_lines = []
    seen = set()
    seen16800 = set()

    def _add(lst, line):
        if line and line not in seen:
            seen.add(line)
            lst.append(line)

    # Beacon PMKIDs
    for bssid_hex, (ssid, pmkid) in results["beacon_pmkids"].items():
        net = results["ssids"].get(bssid_hex, {})
        sec = net.get("security", "Unknown")
        if security_is_sae(sec) or security_is_enterprise(sec):
            continue
        if "22000" in formats:
            line, _ = build_22000_pmkid(bssid_hex, "0" * 12, ssid, pmkid)
            _add(eapol_pmkid_lines, line)
        if "16800" in formats:
            l16, _ = build_16800_pmkid(bssid_hex, "0" * 12, ssid, pmkid)
            if l16 and l16 not in seen16800:
                seen16800.add(l16); pmkid16800_lines.append(l16)

    # EAPOL + PMKID (M1)
    for (bssid_hex, sta_hex), g in results["groups"].items():
        net = results["ssids"].get(bssid_hex)
        ssid = net["ssid"] if net else None
        sec = net["security"] if net else "Unknown"
        if security_is_sae(sec) or security_is_enterprise(sec):
            continue
        if ssid is None:
            continue
        if "22000" in formats:
            line, _ = build_22000_eapol(g, ssid)
            _add(eapol_pmkid_lines, line)
        if g.pmkid:
            if "22000" in formats:
                pline, _ = build_22000_pmkid(bssid_hex, sta_hex, ssid, g.pmkid)
                _add(eapol_pmkid_lines, pline)
            if "16800" in formats:
                p16, _ = build_16800_pmkid(bssid_hex, sta_hex, ssid, g.pmkid)
                if p16 and p16 not in seen16800:
                    seen16800.add(p16); pmkid16800_lines.append(p16)

    # SAE
    sae_incomplete = 0
    for (bssid_hex, sta_hex), g in results["sae_groups"].items():
        net = results["ssids"].get(bssid_hex)
        ssid = net["ssid"] if net else None
        if ssid is None:
            continue
        if not g.is_complete():
            sae_incomplete += 1
            if sae_warn:
                warn(f"SAE handshake incomplete for BSSID={bssid_hex} "
                     f"STA={sta_hex} — saving partial")
        line, _ = build_sae_hash(g, ssid, bssid_hex, sta_hex)
        _add(sae_lines, line)

    # Enterprise — MSCHAPv2 (best-effort; full challenge/response requires
    # deeper EAP parsing; we just report count here)
    # (Placeholder: real MSCHAPv2 extraction is out of scope for this pass.)

    # Write files
    if eapol_pmkid_lines:
        p = os.path.join(output_dir, f"{base}.22000")
        with open(p, "w") as f:
            f.write("\n".join(eapol_pmkid_lines) + "\n")
        written["22000"] = (p, len(eapol_pmkid_lines))

    if pmkid16800_lines:
        p = os.path.join(output_dir, f"{base}.16800")
        with open(p, "w") as f:
            f.write("\n".join(pmkid16800_lines) + "\n")
        written["16800"] = (p, len(pmkid16800_lines))

    if sae_lines:
        p = os.path.join(output_dir, f"{base}.sae")
        with open(p, "w") as f:
            f.write("\n".join(sae_lines) + "\n")
        written["sae"] = (p, len(sae_lines))
        if sae_incomplete:
            written["sae_warn"] = sae_incomplete

    if mschap_lines:
        p = os.path.join(output_dir, f"{base}.5500")
        with open(p, "w") as f:
            f.write("\n".join(mschap_lines) + "\n")
        written["5500"] = (p, len(mschap_lines))

    return written


# ============================================================================
# CLI commands
# ============================================================================

def parse_common(args):
    """Parse common flags: -o, -t, --s, --no-progress, etc."""
    out = {"input": None, "output": None, "save_dir": None,
           "threads": 0, "no_progress": False, "chunk_size": 10000}
    i = 0
    while i < len(args):
        a = args[i]
        if a == "-o" and i + 1 < len(args):
            out["output"] = args[i + 1]; i += 2; continue
        if a == "--s" and i + 1 < len(args):
            out["save_dir"] = args[i + 1]; i += 2; continue
        if a == "-t" and i + 1 < len(args):
            try: out["threads"] = int(args[i + 1])
            except ValueError: pass
            i += 2; continue
        if a == "--no-progress":
            out["no_progress"] = True; i += 1; continue
        if a == "--chunk-size" and i + 1 < len(args):
            try: out["chunk_size"] = int(args[i + 1])
            except ValueError: pass
            i += 2; continue
        if out["input"] is None:
            out["input"] = a
        i += 1
    return out


def cmd_analyze(args):
    opts = parse_common(args)
    if not opts["input"]:
        err("no input file given"); return 1
    if not os.path.isfile(opts["input"]):
        err(f"file not found: {opts['input']}"); return 1

    ok(f"Input      : {opts['input']}")
    try:
        with open(opts["input"], "rb") as f:
            magic = f.read(4)
        if magic == PCAPNG_MAGIC:
            fmt = "pcapng"
        elif magic in (PCAP_MAGIC_LE, PCAP_MAGIC_BE):
            fmt = "pcap"
        else:
            fmt = "unknown"
        ok(f"Format     : {fmt}")
    except Exception:
        pass
    ok(f"Threads    : {opts['threads'] or min(8, os.cpu_count() or 4)}")

    try:
        results = analyze_capture(opts["input"],
                                  threads=opts["threads"],
                                  chunk_size=opts["chunk_size"],
                                  show_progress=not opts["no_progress"])
    except ValueError as e:
        err(str(e)); return 1

    print()
    ok(f"Processed  : {results['packet_count']} packets in "
       f"{results['elapsed']:.2f}s")
    lts = ", ".join(linktype_name(lt) for lt in sorted(results["linktypes_seen"]))
    ok(f"Link type  : {lts or '?'}")
    print()

    report_networks(results, show_clients=True, show_channels=True,
                    show_pmkid=True)
    print()
    report_frame_stats(results)
    print()
    report_sae(results)
    print()
    report_enterprise(results)
    print()
    report_summary_counts(results)

    want_full = any(f in args for f in ("--full", "--stats", "--packets",
                                        "--payloads"))
    if want_full:
        print()
        full = full_packet_scan(opts["input"],
                                show_progress=not opts["no_progress"])
        if "--stats" in args or "--full" in args:
            print()
            report_packet_stats(full)
        if "--packets" in args or "--full" in args:
            print()
            report_packet_list(full)
        if "--payloads" in args or "--full" in args:
            print()
            report_packet_payloads(full)
        if opts["output"]:
            export_report(full, opts["output"])
            print()
            ok(f"Exported full packet report -> {opts['output']}")

    print()
    print_separator("Next Steps")
    eapol_exists = any(g.best_pair()[0] is not None
                       for g in results["groups"].values())
    sae_exists = any(g.is_complete() for g in results["sae_groups"].values())
    if eapol_exists or results["beacon_pmkids"]:
        print(f"  Extract hashes:  {C.CYAN}{PROG} -e {opts['input']} "
              f"--s ./hashes{C.RESET}")
    if sae_exists:
        print(f"  Extract SAE   :  {C.CYAN}{PROG} -sae {opts['input']} "
              f"--s ./hashes{C.RESET}")
    if not eapol_exists and not results["beacon_pmkids"] and not sae_exists:
        info("No hashes available for extraction")
    return 0


def cmd_extract(args):
    opts = parse_common(args)
    if not opts["input"]:
        err("no input file given"); return 1
    if not os.path.isfile(opts["input"]):
        err(f"file not found: {opts['input']}"); return 1

    ok(f"Extracting from {opts['input']}")
    if opts["save_dir"]:
        ok(f"Output directory: {opts['save_dir']}")

    try:
        results = analyze_capture(opts["input"],
                                  threads=opts["threads"],
                                  chunk_size=opts["chunk_size"],
                                  show_progress=not opts["no_progress"])
    except ValueError as e:
        err(str(e)); return 1

    fmt_arg = None
    if "--format" in args:
        fi = args.index("--format")
        if fi + 1 < len(args):
            fmt_arg = args[fi + 1]
    formats = None
    if fmt_arg and fmt_arg != "all":
        formats = set(fmt_arg.split(","))

    print()
    written = write_hash_files(results, opts["input"], opts["save_dir"],
                               formats=formats)

    if not written:
        err("No hashes could be extracted")
        return 1

    print_separator("Files Saved")
    for k, v in written.items():
        if k == "sae_warn":
            warn(f"{v} incomplete SAE handshake(s) saved with warning")
            continue
        path, count = v
        if k == "22000":
            print(f"  {C.GREEN}{path}{C.RESET}  ({count} hashes)")
        elif k == "16800":
            print(f"  {C.GREEN}{path}{C.RESET}  ({count} PMKID-only hashes)")
        elif k == "sae":
            print(f"  {C.GREEN}{path}{C.RESET}  ({count} SAE hashes)")
        elif k == "5500":
            print(f"  {C.GREEN}{path}{C.RESET}  ({count} MSCHAPv2)")

    print()
    print_separator("Crack Commands")
    if "22000" in written:
        print(f"  hashcat -m 22000 {written['22000'][0]} wordlist.txt")
    if "16800" in written:
        print(f"  hashcat -m 16800 {written['16800'][0]} wordlist.txt")
    if "sae" in written:
        print(f"\n  {C.YELLOW}WPA3-SAE requires online attack with wacker:"
              f"{C.RESET}")
        print(f"    sudo python3 wacker.py --interface wlan0 \\")
        print(f"        --wordlist wordlist.txt --bssid <BSSID>")
    if "5500" in written:
        print(f"\n  hashcat -m 5500 {written['5500'][0]} wordlist.txt")
    return 0


def cmd_inspect(args):
    opts = parse_common(args)
    show_clients = "--show-clients" in args
    show_sae = "--show-sae" in args
    show_ent = "--show-enterprise" in args
    show_pmkid = "--show-pmkid" in args
    show_channels = "--show-channels" in args

    if not opts["input"]:
        err("no input file given"); return 1
    if not os.path.isfile(opts["input"]):
        err(f"file not found: {opts['input']}"); return 1

    try:
        results = analyze_capture(opts["input"],
                                  threads=opts["threads"],
                                  chunk_size=opts["chunk_size"],
                                  show_progress=not opts["no_progress"])
    except ValueError as e:
        err(str(e)); return 1

    print()
    report_networks(results,
                    show_clients=show_clients or True,
                    show_pmkid=show_pmkid,
                    show_channels=show_channels)
    if show_sae:
        print(); report_sae(results, verbose=True)
    if show_ent:
        print(); report_enterprise(results, verbose=True)
    return 0


def cmd_sae(args):
    opts = parse_common(args)
    check_h2e = "--check-h2e" in args
    if not opts["input"]:
        err("no input file given"); return 1
    if not os.path.isfile(opts["input"]):
        err(f"file not found: {opts['input']}"); return 1

    try:
        results = analyze_capture(opts["input"],
                                  threads=opts["threads"],
                                  chunk_size=opts["chunk_size"],
                                  show_progress=not opts["no_progress"])
    except ValueError as e:
        err(str(e)); return 1

    print()
    report_sae(results, verbose=True)

    if check_h2e:
        print()
        print_separator("H2E Support Check")
        for bssid_hex, info in results["ssids"].items():
            if security_is_sae(info.get("security", "")):
                h2e = info.get("h2e_support", False)
                ssid = info.get("ssid", "?")
                mark = f"{C.GREEN}YES{C.RESET}" if h2e else f"{C.YELLOW}NO{C.RESET}"
                print(f"  {ssid:<20} {bssid_hex:<18} H2E: {mark}")

    if opts["save_dir"] is not None or any(g.is_complete()
                                            for g in results["sae_groups"].values()):
        print()
        written = write_hash_files(results, opts["input"], opts["save_dir"])
        if "sae" in written:
            path, count = written["sae"]
            ok(f"SAE hashes saved: {path} ({count})")
            info("Use wacker/dragonslayer for online cracking")
        else:
            warn("No complete SAE handshakes to save")
    return 0


def cmd_enterprise(args):
    opts = parse_common(args)
    if not opts["input"]:
        err("no input file given"); return 1
    if not os.path.isfile(opts["input"]):
        err(f"file not found: {opts['input']}"); return 1

    try:
        results = analyze_capture(opts["input"],
                                  threads=opts["threads"],
                                  chunk_size=opts["chunk_size"],
                                  show_progress=not opts["no_progress"])
    except ValueError as e:
        err(str(e)); return 1

    print()
    report_enterprise(results, verbose=True)
    if not results["enterprise_frames"]:
        info("No 802.1X Enterprise traffic detected")
        return 0

    if "--creds" not in args:
        info("Run with --creds to extract any crackable EAP-MD5 / "
             "EAP-MSCHAPv2 material from this capture")
        return 0

    if not ENTERPRISE_MODULE_AVAILABLE:
        err("wiforge_enterprise.py was not found next to this script — "
            "--creds needs it")
        return 1

    print()
    print_separator("Enterprise Credential Extraction")
    collector = _ent.scan_enterprise_capture(
        opts["input"], open_reader, parse_radiotap, parse_80211_header,
        FragBuffer, FT_DATA, show_progress=not opts["no_progress"],
        progress_cls=ProgressBar)

    found = _ent.report_enterprise_creds(collector, print)
    if not found:
        print()
        warn("no crackable EAP-MD5/MSCHAPv2 material found — if this "
             "network uses PEAP/TTLS, the inner credentials are inside "
             "an encrypted TLS tunnel this capture can't reveal (see the "
             "docstring in wiforge_enterprise.py for what this can and "
             "can't recover)")
        return 0

    out_dir = opts["save_dir"] or (os.path.dirname(
        os.path.abspath(opts["input"])) or ".")
    os.makedirs(out_dir, exist_ok=True)
    base = os.path.splitext(os.path.basename(opts["input"]))[0]
    written = _ent.write_enterprise_hashes(collector, out_dir, base)

    print()
    print_separator("Files Saved")
    for k, (path, count) in written.items():
        print(f"  {C.GREEN}{path}{C.RESET}  ({count} hashes)")

    print()
    print_separator("Crack Commands")
    if "5500" in written:
        print(f"  hashcat -m 5500 {written['5500'][0]} wordlist.txt")
    if "4800" in written:
        print(f"  hashcat -m 4800 {written['4800'][0]} wordlist.txt")
    return 0


def cmd_merge(args):
    output = None
    inputs = []
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-o", "--output") and i + 1 < len(args):
            output = args[i + 1]; i += 2; continue
        inputs.append(a); i += 1

    if not inputs or not output:
        err("usage: Wiforge -m <files...> -o <output>")
        return 1

    lines = set()
    total = 0
    for f in inputs:
        if not os.path.isfile(f):
            warn(f"skipping missing file: {f}"); continue
        with open(f, "r", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                total += 1
                lines.add(line)

    with open(output, "w") as fh:
        for line in sorted(lines):
            fh.write(line + "\n")

    ok(f"Merged {len(inputs)} files")
    ok(f"Total lines : {total}")
    ok(f"Unique      : {len(lines)}")
    ok(f"Saved to    : {output}")
    return 0


def cmd_convert(args):
    output = None
    inp = None
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-o", "--output") and i + 1 < len(args):
            output = args[i + 1]; i += 2; continue
        if inp is None:
            inp = a
        i += 1

    if not inp or not output:
        err("usage: Wiforge -c <input> -o <output>")
        return 1
    if not os.path.isfile(inp):
        err(f"file not found: {inp}"); return 1

    in_ext = os.path.splitext(inp)[1].lower()
    out_ext = os.path.splitext(output)[1].lower()

    # pcap -> pcapng
    if in_ext == ".pcap" and out_ext == ".pcapng":
        return _convert_pcap_to_pcapng(inp, output)
    # pcapng -> pcap
    if in_ext == ".pcapng" and out_ext == ".pcap":
        return _convert_pcapng_to_pcap(inp, output)
    # hash file -> txt
    if in_ext in (".22000", ".sae", ".5500") and out_ext == ".txt":
        with open(inp, "r", errors="replace") as fi, open(output, "w") as fo:
            for line in fi:
                fo.write(line)
        ok(f"Converted {inp} -> {output}")
        return 0

    err(f"unsupported conversion: {in_ext} -> {out_ext}")
    return 1


def _convert_pcap_to_pcapng(inp, out):
    """Minimal pcap -> pcapng converter."""
    with open(inp, "rb") as f:
        header = f.read(24)
        magic = header[0:4]
        if magic == PCAP_MAGIC_LE:
            endian = "<"
        elif magic == PCAP_MAGIC_BE:
            endian = ">"
        else:
            err("not a pcap file"); return 1
        network = struct.unpack(endian + "I", header[20:24])[0]
        with open(out, "wb") as o:
            # SHB
            shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
            shb_len = 8 + len(shb_body) + 4
            o.write(struct.pack("<I", 0x0A0D0D0A))
            o.write(struct.pack("<I", shb_len))
            o.write(shb_body)
            o.write(struct.pack("<I", shb_len))
            # IDB
            idb_body = struct.pack("<HHI", network, 0, 0)
            idb_len = 8 + len(idb_body) + 4
            o.write(struct.pack("<I", 0x00000001))
            o.write(struct.pack("<I", idb_len))
            o.write(idb_body)
            o.write(struct.pack("<I", idb_len))
            # EPBs
            while True:
                ph = f.read(16)
                if len(ph) < 16: break
                ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
                    endian + "IIII", ph)
                pkt = f.read(incl_len)
                if len(pkt) < incl_len: break
                ts = (ts_sec << 32) | ts_usec
                pad = (-len(pkt)) % 4
                epb_body = struct.pack("<IIIII", 0, ts >> 32, ts & 0xFFFFFFFF,
                                       len(pkt), orig_len) + pkt + b"\x00" * pad
                epb_len = 8 + len(epb_body) + 4
                o.write(struct.pack("<I", 0x00000006))
                o.write(struct.pack("<I", epb_len))
                o.write(epb_body)
                o.write(struct.pack("<I", epb_len))
    ok(f"Converted {inp} -> {out}")
    return 0


def _convert_pcapng_to_pcap(inp, out):
    """Minimal pcapng -> pcap converter (only first interface)."""
    reader = open_reader(inp)
    if not isinstance(reader, PcapngReader):
        err("not a pcapng file"); return 1
    linktype = 105
    packets = []
    try:
        for lt, ts, pkt in reader:
            linktype = lt
            packets.append((ts, pkt))
    finally:
        reader.close()
    with open(out, "wb") as o:
        o.write(PCAP_MAGIC_LE)
        o.write(struct.pack("<HHIIII", 2, 4, 0, 0, 65535, linktype))
        for ts, pkt in packets:
            sec = int(ts)
            usec = int((ts - sec) * 1_000_000)
            o.write(struct.pack("<IIII", sec, usec, len(pkt), len(pkt)))
            o.write(pkt)
    ok(f"Converted {inp} -> {out} ({len(packets)} packets)")
    return 0


def cmd_verify(args):
    opts = parse_common(args)
    if not opts["input"]:
        err("no input file given"); return 1
    f = opts["input"]
    if not os.path.isfile(f):
        err(f"file not found: {f}"); return 1

    ok(f"File   : {f}")
    size = os.path.getsize(f)
    ok(f"Size   : {size} bytes")

    with open(f, "rb") as fh:
        magic = fh.read(4)

    if magic == PCAPNG_MAGIC:
        ok("Format : pcapng")
        try:
            reader = open_reader(f)
            n = 0
            for _ in reader:
                n += 1
                if n > 1_000_000: break
            reader.close()
            ok(f"Packets: {n}{'+' if n > 1_000_000 else ''}")
            ok(f"Status : {C.GREEN}✓ VALID{C.RESET}")
        except Exception as e:
            err(f"Invalid: {e}")
            return 1
    elif magic in (PCAP_MAGIC_LE, PCAP_MAGIC_BE):
        ok("Format : pcap")
        try:
            reader = open_reader(f)
            n = 0
            for _ in reader:
                n += 1
            reader.close()
            ok(f"Packets: {n}")
            ok(f"Status : {C.GREEN}✓ VALID{C.RESET}")
        except Exception as e:
            err(f"Invalid: {e}")
            return 1
    else:
        # Try as hash file
        try:
            with open(f, "r", errors="replace") as fh:
                lines = [l.strip() for l in fh if l.strip()]
            hash_types = defaultdict(int)
            for l in lines:
                if l.startswith("WPA*01*"): hash_types["PMKID"] += 1
                elif l.startswith("WPA*02*"): hash_types["EAPOL"] += 1
                elif l.startswith("WPA*03*"): hash_types["SAE"] += 1
                elif l.startswith("$NETNTLM$"): hash_types["MSCHAPv2"] += 1
                else: hash_types["Unknown"] += 1
            ok(f"Format : hash file ({len(lines)} lines)")
            for k, v in hash_types.items():
                ok(f"  {k:<10}: {v}")
            ok(f"Status : {C.GREEN}✓ VALID{C.RESET}")
        except Exception as e:
            err(f"Unknown format: {e}")
            return 1
    return 0


def is_multicast_mac(b):
    return bool(b[0] & 0x01)


def write_pcap_ethernet(path, frames):
    """frames: list of (ts_float, eth_bytes). Writes a classic-pcap file
    with DLT_EN10MB (1) so Wireshark opens it as plain decrypted Ethernet."""
    with open(path, "wb") as f:
        f.write(PCAP_MAGIC_LE)
        f.write(struct.pack("<HHIIII", 2, 4, 0, 0, 262144, 1))
        for ts, data in frames:
            sec = int(ts)
            usec = int((ts - sec) * 1_000_000)
            f.write(struct.pack("<IIII", sec, usec, len(data), len(data)))
            f.write(data)


def summarize_ethernet(eth):
    if len(eth) < 14:
        return "truncated", None
    ethertype = struct.unpack_from(">H", eth, 12)[0]
    payload = eth[14:]
    return summarize_plaintext_llc(ethertype, payload), ethertype


def cmd_decrypt(args):
    opts = parse_common(args)
    if not opts["input"]:
        err("no input file given"); return 1
    if not os.path.isfile(opts["input"]):
        err(f"file not found: {opts['input']}"); return 1
    if not CRYPTO_AVAILABLE:
        err("the 'cryptography' package is required for -d/--decrypt")
        info("install it with: pip install cryptography"); return 1

    password = None
    target_bssid = None
    target_sta = None
    i = 0
    while i < len(args):
        if args[i] == "-p" and i + 1 < len(args):
            password = args[i + 1]; i += 2; continue
        if args[i] == "--bssid" and i + 1 < len(args):
            target_bssid = args[i + 1].lower().replace(":", ""); i += 2; continue
        if args[i] == "--sta" and i + 1 < len(args):
            target_sta = args[i + 1].lower().replace(":", ""); i += 2; continue
        i += 1
    if not password:
        err("usage: Wiforge -d <capture> -p <password> [--bssid MAC] "
            "[--sta MAC] [--s outdir]")
        return 1

    try:
        results = analyze_capture(opts["input"], threads=opts["threads"],
                                  chunk_size=opts["chunk_size"],
                                  show_progress=not opts["no_progress"])
    except ValueError as e:
        err(str(e)); return 1

    # Pick the target BSSID/STA pair
    candidates = []
    for (bssid_hex, sta_hex), g in results["groups"].items():
        if g.best_pair()[0] is None:
            continue
        if target_bssid and bssid_hex != target_bssid:
            continue
        if target_sta and sta_hex != target_sta:
            continue
        net = results["ssids"].get(bssid_hex, {})
        if security_is_sae(net.get("security", "")) or \
                security_is_enterprise(net.get("security", "")):
            continue
        candidates.append((bssid_hex, sta_hex, g, net))

    if not candidates:
        err("no matching WPA/WPA2-PSK handshake found for the given "
            "--bssid/--sta (or none in the capture)")
        return 1
    if len(candidates) > 1:
        err("multiple candidate handshakes found — narrow with --bssid "
            "(and --sta if needed):")
        for b, s, g, net in candidates:
            info(f"  BSSID={b} STA={s} SSID={net.get('ssid')!r}")
        return 1

    bssid_hex, sta_hex, group, net = candidates[0]
    ssid = net.get("ssid")
    if ssid is None:
        err("SSID for this network was not seen in the capture (no beacon)")
        return 1

    pairwise = (net.get("rsn") or {}).get("pairwise", [])
    if any(CIPHER_MAP.get(c) == "TKIP" for c in pairwise):
        err("this network uses TKIP — TKIP decryption is not implemented "
            "in this version of Wiforge (CCMP/AES only)")
        return 1

    ok(f"Target     : SSID={ssid!r} BSSID={bssid_hex} STA={sta_hex}")
    verified, keymat, reason = verify_password_against_group(
        password, ssid, bssid_hex, sta_hex, group)
    if not verified:
        err(f"password check failed: {reason}")
        return 1
    kdv = keymat.get("key_desc_version")
    algo = "AES-128-CMAC / KDF-SHA256 (*-SHA256 AKM)" if kdv == 3 \
        else "HMAC-SHA1 / PRF-384 (standard WPA2-PSK)"
    ok(f"{C.GREEN}Password verified via MIC match{C.RESET}  [{algo}]")

    gtk = None
    m3 = group.msgs.get(3)
    if m3 is not None and m3["key_data_len"] > 0:
        raw = m3["raw"]
        key_data = raw[99:99 + m3["key_data_len"]]
        gtk = unwrap_gtk_from_m3(key_data, keymat["kek"])
        if gtk:
            ok("GTK recovered from M3 — broadcast/multicast traffic "
               "(ARP, DHCP, etc.) will be decrypted too")
        else:
            warn("could not recover GTK from M3 — only unicast traffic "
                 "for this STA will be decrypted")
    else:
        warn("no M3 captured — only unicast traffic for this STA will be "
             "decrypted (no GTK available)")

    tk = keymat["tk"]
    target_bssid_bytes = bytes.fromhex(bssid_hex)
    target_sta_bytes = bytes.fromhex(sta_hex)

    print()
    reader = open_reader(opts["input"])
    progress = ProgressBar(0, prefix="Decrypting",
                           enable=not opts["no_progress"] and sys.stderr.isatty())
    try:
        file_size = os.path.getsize(opts["input"])
        progress.total = max(file_size // 200, 1000)
    except Exception:
        progress.total = 1000

    scanned = 0
    attempted = 0
    decrypted_uni = 0
    decrypted_grp = 0
    failed = 0
    eth_frames = []
    proto_counts = defaultdict(int)

    try:
        for linktype, ts, pkt in reader:
            progress.update(1)
            rt = parse_radiotap(pkt)
            pkt2 = rt["body"]
            h = parse_80211_header(pkt2)
            if h is None or h["ftype"] != FT_DATA or not h["protected"]:
                continue
            if bytes(h["addr3"]) != target_bssid_bytes:
                continue
            scanned += 1
            is_grp = is_multicast_mac(bytes(h["addr1"]))
            if not is_grp and bytes(h["addr2"]) != target_sta_bytes and \
                    bytes(h["addr1"]) != target_sta_bytes:
                continue
            key = gtk if is_grp else tk
            if key is None or (is_grp and len(key) not in (16,)):
                continue
            attempted += 1
            plain_llc = ccmp_decrypt_data(pkt2, h, key[:16])
            if plain_llc is None:
                failed += 1
                continue
            eth = dot11_to_ethernet(h, plain_llc)
            if eth is None:
                failed += 1
                continue
            if is_grp:
                decrypted_grp += 1
            else:
                decrypted_uni += 1
            eth_frames.append((ts, eth))
            summary, _ = summarize_ethernet(eth)
            proto_counts[summary.split()[0] if summary else "?"] += 1
    finally:
        reader.close()
        progress.close()

    print()
    print_separator("Decryption Summary")
    print(f"  CCMP frames for this BSSID : {scanned}")
    print(f"  Decrypt attempted          : {attempted}")
    print(f"  Decrypted (unicast / TK)   : {C.GREEN}{decrypted_uni}{C.RESET}")
    print(f"  Decrypted (group / GTK)    : {C.GREEN}{decrypted_grp}{C.RESET}")
    print(f"  Failed (bad key/auth tag)  : "
          f"{C.YELLOW if failed else ''}{failed}{C.RESET if failed else ''}")
    if proto_counts:
        print(f"  {C.DIM}Protocols seen in decrypted traffic:{C.RESET}")
        for name, n in sorted(proto_counts.items(), key=lambda kv: -kv[1]):
            print(f"    {name:<10}: {n}")

    if eth_frames:
        out_dir = opts["save_dir"] or (os.path.dirname(
            os.path.abspath(opts["input"])) or ".")
        os.makedirs(out_dir, exist_ok=True)
        base = os.path.splitext(os.path.basename(opts["input"]))[0]
        pcap_out = os.path.join(out_dir, f"{base}-decrypted.pcap")
        write_pcap_ethernet(pcap_out, eth_frames)
        print()
        ok(f"Decrypted traffic written  : {C.GREEN}{pcap_out}{C.RESET} "
           f"(open in Wireshark as Ethernet)")
        if opts["output"]:
            records = []
            for (ts, eth) in eth_frames:
                summary, _ = summarize_ethernet(eth)
                records.append({"ts": ts, "summary": summary, "len": len(eth)})
            export_report({"total": len(records), "mgmt": 0, "ctrl": 0,
                           "data": len(records), "data_encrypted": 0,
                           "data_plaintext": len(records), "unparsable": 0,
                           "by_subtype": {}, "records": records,
                           "truncated": False, "elapsed": 0.0}, opts["output"])
            ok(f"Report exported            : {opts['output']}")
    else:
        warn("nothing was decrypted — no matching frames, or key material "
             "did not validate against any captured frame")
    return 0


def cmd_auto(args):
    """Pipeline mode: analyze -> extract hashes -> (if -p given) decrypt.
    Without -p, stops after extraction and tells the user how to resume."""
    opts = parse_common(args)
    password = None
    for i, a in enumerate(args):
        if a == "-p" and i + 1 < len(args):
            password = args[i + 1]
    if not opts["input"]:
        err("usage: Wiforge --auto <capture> [-p password] [--s outdir]")
        return 1

    print_separator("AUTO: Step 1/3 — Analyze")
    rc = cmd_analyze([a for a in args if a != "-p" and a != password])
    if rc != 0:
        return rc

    print()
    print_separator("AUTO: Step 2/3 — Extract hashes")
    rc = cmd_extract([a for a in args if a != "-p" and a != password])

    if not password:
        print()
        print_separator("AUTO: Step 3/3 — Decrypt (skipped)")
        info("No -p password given — crack the extracted hash externally, "
             f"then re-run:")
        print(f"    {C.CYAN}{PROG} --auto {opts['input']} -p <password> "
              f"--s {opts['save_dir'] or './hashes'}{C.RESET}")
        return rc

    print()
    print_separator("AUTO: Step 3/3 — Decrypt")
    return cmd_decrypt(args)


def cmd_help(args=None):
    print(f"""{C.BOLD}USAGE:{C.RESET}
    {PROG} <flag> <input> [options]

{C.BOLD}FLAGS:{C.RESET}
    {C.GREEN}-a{C.RESET}          Analyze capture (default)
    {C.GREEN}-e{C.RESET}          Extract all hashes to files
    {C.GREEN}-i{C.RESET}          Inspect networks (no hash generation)
    {C.GREEN}-sae{C.RESET}        WPA3-SAE operations
    {C.GREEN}-ent{C.RESET}        802.1X Enterprise operations
    {C.GREEN}-m{C.RESET}          Merge multiple hash files
    {C.GREEN}-c{C.RESET}          Convert between formats
    {C.GREEN}-v{C.RESET}          Verify capture or hash file
    {C.GREEN}-d{C.RESET}          Decrypt traffic once you have the password
    {C.GREEN}--auto{C.RESET}      Full pipeline: analyze -> extract -> decrypt
    {C.GREEN}-h{C.RESET}          Show this help

{C.BOLD}COMMON OPTIONS:{C.RESET}
    {C.CYAN}--s PATH{C.RESET}     Save hash/decrypted files to PATH
    {C.CYAN}-o FILE{C.RESET}      Output file (.json/.csv/.txt for reports;
                   also used with -m/-c)
    {C.CYAN}-p PASS{C.RESET}      Password (with -d/--auto)
    {C.CYAN}--bssid / --sta{C.RESET}  Target a specific network/client (-d)
    {C.CYAN}--creds{C.RESET}      Extract real EAP-MD5/MSCHAPv2 creds (-ent)
    {C.CYAN}-t N{C.RESET}         Number of threads (default: auto)
    {C.CYAN}--no-progress{C.RESET} Disable progress bar

{C.BOLD}-a REPORT OPTIONS:{C.RESET}
    {C.CYAN}--stats{C.RESET}      Full packet counts incl. encrypted vs plaintext
    {C.CYAN}--packets{C.RESET}    Per-packet list (src/dst, type, summary)
    {C.CYAN}--payloads{C.RESET}   Per-packet hex/ascii payload dump
    {C.CYAN}--full{C.RESET}       All three of the above

{C.BOLD}EXAMPLES:{C.RESET}
    {PROG} -a wire4-01.cap
    {PROG} -a wire4-01.cap --full -o report.json
    {PROG} -e wire4-01.cap --s ./hashes --format 22000,16800
    {PROG} -i wire4-01.cap --show-clients
    {PROG} -sae wire4-01.cap
    {PROG} -ent wire4-01.cap
    {PROG} -ent wire4-01.cap --creds --s ./hashes
    {PROG} -d wire4-01.cap -p 'the-password' --s ./out
    {PROG} --auto wire4-01.cap -p 'the-password' --s ./out
    {PROG} -m a.22000 b.22000 -o combined.22000
    {PROG} -c input.pcap -o output.pcapng
    {PROG} -v wire4-01.cap

{C.DIM}Hash file formats:
    .22000  -> WPA/WPA2 EAPOL + PMKID (hashcat -m 22000)
    .16800  -> WPA2 PMKID only (hashcat -m 16800)
    .sae    -> WPA3-SAE (wacker/dragonslayer, online only)
    .5500   -> EAP-MSCHAPv2, via -ent --creds (hashcat -m 5500)
    .4800   -> EAP-MD5, via -ent --creds (hashcat -m 4800){C.RESET}
""")


# ============================================================================
# Main dispatcher
# ============================================================================

def main():
    args = sys.argv[1:]

    # Banner always shown
    banner()

    if not args or args[0] in ("-h", "--help"):
        cmd_help()
        return 0

    flag = args[0]
    rest = args[1:]

    handlers = {
        "-a":   cmd_analyze,
        "-e":   cmd_extract,
        "-i":   cmd_inspect,
        "-sae": cmd_sae,
        "-ent": cmd_enterprise,
        "-m":   cmd_merge,
        "-c":   cmd_convert,
        "-v":   cmd_verify,
        "-d":   cmd_decrypt,
        "--auto": cmd_auto,
    }

    # Default: if first arg is a file, treat as analyze
    if flag not in handlers:
        if os.path.isfile(flag):
            return cmd_analyze(args)
        err(f"Unknown flag: {flag}")
        print()
        cmd_help()
        return 1

    return handlers[flag](rest)


if __name__ == "__main__":
    try:
        sys.exit(main() or 0)
    except KeyboardInterrupt:
        print()
        err("Interrupted")
        sys.exit(130)