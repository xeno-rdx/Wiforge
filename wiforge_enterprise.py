"""
wiforge_enterprise.py — Wiforge Enterprise (802.1X) credential extraction
===========================================================================

Extension module for Wiforge. Where the main tool's `-ent` only detects
that EAP traffic is present, this module actually parses the EAP packets
and pulls out crackable material:

  * EAP-Identity (type 1)        -> the username, almost always sent in
                                     the clear even under PEAP/TTLS.
  * EAP-MD5-Challenge (type 4)   -> Challenge + Response -> hashcat -m 4800
                                     (iSCSI CHAP / MD5(CHAP) — same
                                     construction: MD5(ID || secret ||
                                     Challenge), per RFC 1994 / RFC 3748).
  * EAP-MSCHAPv2 (type 26)       -> AuthenticatorChallenge + PeerChallenge
                                     + NT-Response -> hashcat -m 5500
                                     (NetNTLMv1), after folding the three
                                     values into the single 8-byte
                                     "Challenge" hashcat expects, via the
                                     ChallengeHash() function from RFC
                                     2759 §8.2 (SHA1(PeerChallenge ||
                                     AuthenticatorChallenge || Username),
                                     first 8 bytes). This is the same
                                     transform used by asleap/chapcrack —
                                     "MSCHAPv2 can [then] be cracked in
                                     the same way as MSCHAP(v1)".

IMPORTANT SCOPE NOTE (read before relying on this against a real target):
EAP-MSCHAPv2 is almost always run INSIDE a TLS tunnel (PEAP or EAP-TTLS).
When that's the case, these EAP-MSCHAPv2 packets are themselves encrypted
by the outer TLS session and are NOT visible in a plain Wi-Fi capture —
this module can't see inside a TLS tunnel it has no key for. It CAN
recover credentials when:
    1) the network runs *outer* EAP-MSCHAPv2 or EAP-MD5 directly, with no
       PEAP/TTLS tunnel (occurs, though PEAP-wrapped MSCHAPv2 is more
       common in practice), or
    2) the capture already contains a decrypted/relayed EAP conversation
       — e.g. one obtained by actively running a rogue AP / evil-twin
       that terminates the TLS tunnel itself (tools like eaphammer /
       hostapd-wpe), rather than a passive capture of someone else's
       PEAP session.
In short: this module reads what's in the capture faithfully, but a
passively-sniffed PEAP/TTLS capture will typically have nothing for it
to extract beyond the outer EAP-Identity (username) and TLS handshake —
and that's a protocol property, not a bug in this code.

No external dependencies — stdlib only (hashlib for SHA1/MD5, struct).
Pulling frames out of the .cap/.pcapng itself is left to the caller
(Wiforge's own radiotap/802.11/EAPOL parsers are passed in), so this
module stays a thin, independently-testable layer on top of raw EAP
bytes and doesn't duplicate Wiforge's packet-framing code.
"""

import hashlib
import struct
from collections import defaultdict

# EAP Code
EAP_REQUEST = 1
EAP_RESPONSE = 2
EAP_SUCCESS = 3
EAP_FAILURE = 4

# EAP Type
EAP_TYPE_IDENTITY = 1
EAP_TYPE_MD5 = 4
EAP_TYPE_TLS = 13
EAP_TYPE_TTLS = 21
EAP_TYPE_PEAP = 25
EAP_TYPE_MSCHAPV2 = 26

TUNNEL_TYPES = {EAP_TYPE_TLS, EAP_TYPE_TTLS, EAP_TYPE_PEAP}

MSCHAPV2_OP_CHALLENGE = 1
MSCHAPV2_OP_RESPONSE = 2
MSCHAPV2_OP_SUCCESS = 3
MSCHAPV2_OP_FAILURE = 4


def parse_eap_packet(eapol):
    """Parse the EAP payload of an EAPOL-EAP-Packet frame. `eapol` is the
    EAPOL bytes (version, type, length, ...) as sliced out of the LLC/SNAP
    body by the caller — same convention Wiforge's own parse_eapol() uses.
    Returns a dict, or None if this isn't a usable EAP packet."""
    if len(eapol) < 4 or eapol[1] != 0:  # type 0 = EAP-Packet
        return None
    eap = eapol[4:]
    if len(eap) < 4:
        return None
    code, identifier = eap[0], eap[1]
    length = struct.unpack_from(">H", eap, 2)[0]
    out = {"code": code, "identifier": identifier, "length": length,
          "eap_type": None, "raw": eap}
    if code not in (EAP_REQUEST, EAP_RESPONSE) or len(eap) < 5:
        return out
    out["eap_type"] = eap[4]
    type_data = eap[5:]

    if out["eap_type"] == EAP_TYPE_IDENTITY:
        try:
            out["identity"] = type_data.decode("utf-8", "replace")
        except Exception:
            out["identity"] = type_data.decode("latin-1", "replace")

    elif out["eap_type"] == EAP_TYPE_MD5:
        if len(type_data) < 1:
            return out
        value_size = type_data[0]
        value = type_data[1:1 + value_size]
        if len(value) != value_size:
            return out
        out["md5_value"] = value  # Challenge (Request) or Response (Response)
        name = type_data[1 + value_size:]
        if name:
            out["name"] = name.decode("utf-8", "replace")

    elif out["eap_type"] == EAP_TYPE_MSCHAPV2:
        if len(type_data) < 2:
            return out
        opcode = type_data[0]
        mschap_id = type_data[1]
        out["mschapv2_opcode"] = opcode
        out["mschapv2_id"] = mschap_id
        if len(type_data) < 6:
            return out
        value_size = type_data[4]
        value = type_data[5:5 + value_size]
        name = type_data[5 + value_size:]
        if name:
            try:
                out["name"] = name.decode("utf-8", "replace")
            except Exception:
                pass
        if opcode == MSCHAPV2_OP_CHALLENGE and len(value) == value_size \
                and value_size == 16:
            out["auth_challenge"] = bytes(value)
        elif opcode == MSCHAPV2_OP_RESPONSE and len(value) == value_size \
                and value_size == 49:
            out["peer_challenge"] = bytes(value[0:16])
            # value[16:24] is Reserved (8 zero bytes)
            out["nt_response"] = bytes(value[24:48])
            out["flags"] = value[48]

    elif out["eap_type"] in TUNNEL_TYPES:
        out["tunnel"] = True

    return out


class EnterpriseSession:
    """Accumulates EAP state for one (bssid, sta) pair as frames are fed
    in capture order."""

    def __init__(self, bssid_hex, sta_hex):
        self.bssid_hex = bssid_hex
        self.sta_hex = sta_hex
        self.identity = None            # outer EAP-Identity (often anon)
        self.eap_types_seen = set()
        self.saw_tunnel = False
        self.md5_challenges = {}        # identifier -> challenge bytes
        self.md5_creds = []             # list of dict(identifier, challenge, response)
        self.mschap_auth_challenge = {} # identifier -> 16-byte AuthenticatorChallenge
        self.mschap_creds = []          # list of dict(username, peer_challenge,
                                        #   auth_challenge, nt_response)

    def feed(self, eap):
        if eap is None or eap["eap_type"] is None:
            return
        self.eap_types_seen.add(eap["eap_type"])

        if eap["eap_type"] == EAP_TYPE_IDENTITY and eap["code"] == EAP_RESPONSE:
            ident = eap.get("identity", "").strip("\x00").strip()
            if ident:
                self.identity = ident

        elif eap["eap_type"] in TUNNEL_TYPES:
            self.saw_tunnel = True

        elif eap["eap_type"] == EAP_TYPE_MD5:
            ident_byte = eap["identifier"]
            if eap["code"] == EAP_REQUEST and "md5_value" in eap:
                self.md5_challenges[ident_byte] = eap["md5_value"]
            elif eap["code"] == EAP_RESPONSE and "md5_value" in eap:
                challenge = self.md5_challenges.get(ident_byte)
                if challenge is not None:
                    self.md5_creds.append({
                        "identifier": ident_byte,
                        "challenge": challenge,
                        "response": eap["md5_value"],
                        "username": eap.get("name") or self.identity,
                    })

        elif eap["eap_type"] == EAP_TYPE_MSCHAPV2:
            if eap["code"] == EAP_REQUEST and "auth_challenge" in eap:
                self.mschap_auth_challenge[eap["mschapv2_id"]] = eap["auth_challenge"]
            elif eap["code"] == EAP_RESPONSE and "nt_response" in eap:
                auth_chal = self.mschap_auth_challenge.get(eap["mschapv2_id"])
                if auth_chal is not None:
                    username = eap.get("name") or self.identity
                    self.mschap_creds.append({
                        "username": username,
                        "auth_challenge": auth_chal,
                        "peer_challenge": eap["peer_challenge"],
                        "nt_response": eap["nt_response"],
                    })


class EnterpriseCollector:
    """Feed it every EAP packet found in the capture (with its bssid/sta);
    it keeps one EnterpriseSession per (bssid, sta) pair."""

    def __init__(self):
        self.sessions = {}

    def feed(self, bssid_hex, sta_hex, eapol_bytes):
        eap = parse_eap_packet(eapol_bytes)
        if eap is None:
            return
        key = (bssid_hex, sta_hex)
        if key not in self.sessions:
            self.sessions[key] = EnterpriseSession(bssid_hex, sta_hex)
        self.sessions[key].feed(eap)

    def merge(self, other):
        for key, sess in other.sessions.items():
            if key not in self.sessions:
                self.sessions[key] = sess
                continue
            mine = self.sessions[key]
            mine.eap_types_seen |= sess.eap_types_seen
            mine.saw_tunnel = mine.saw_tunnel or sess.saw_tunnel
            mine.identity = mine.identity or sess.identity
            mine.md5_challenges.update(sess.md5_challenges)
            mine.md5_creds.extend(sess.md5_creds)
            mine.mschap_auth_challenge.update(sess.mschap_auth_challenge)
            mine.mschap_creds.extend(sess.mschap_creds)


# ---------------------------------------------------------------------
# RFC 2759 §8.2 ChallengeHash() — folds PeerChallenge + AuthenticatorChallenge
# + Username down to the single 8-byte "Challenge" that the classic
# MSCHAP/NTLMv1 DES response algorithm (and hence hashcat -m 5500) uses.
# ---------------------------------------------------------------------

def mschapv2_challenge_hash(peer_challenge, auth_challenge, username):
    # "MSCHAPv2 does not include optional domain name in the
    # challenge-response calculation, so remove domain prefix" (wpa_supplicant)
    uname = username or ""
    if "\\" in uname:
        uname = uname.split("\\", 1)[1]
    digest = hashlib.sha1(peer_challenge + auth_challenge +
                          uname.encode("utf-8", "replace")).digest()
    return digest[:8]


def build_5500_mschapv2(username, domain, peer_challenge, auth_challenge,
                        nt_response):
    """hashcat -m 5500 (NetNTLMv1) line for a captured MSCHAPv2 exchange.
    MSCHAPv2 has no real LM response, so — following the common
    responder/asleap-style convention — the NT-Response is duplicated
    into the LM slot; only the NT-Response + computed challenge actually
    matter for cracking."""
    if not peer_challenge or not auth_challenge or not nt_response:
        return None
    chal = mschapv2_challenge_hash(peer_challenge, auth_challenge, username)
    nt_hex = nt_response.hex()
    user = (username or "unknown").split("\\")[-1]
    dom = domain or ""
    return f"{user}::{dom}:{nt_hex}:{nt_hex}:{chal.hex()}"


def build_4800_md5chap(identifier, challenge, response):
    """hashcat -m 4800 (MD5(CHAP) / iSCSI CHAP) line. Format confirmed
    against hashcat's own example hash:
    afd09efdd6f8ca9f18ec77c5869788c3:0102...1516:01
    i.e. response:challenge:identifier — all hex, identifier is 1 byte."""
    if len(response) != 16:  # MD5 digest size
        return None
    return f"{response.hex()}:{challenge.hex()}:{identifier:02x}"


def write_enterprise_hashes(collector, output_dir, base):
    """Write .5500 and .4800 files from everything the collector gathered.
    Returns {fmt: (path, count)} like Wiforge's write_hash_files()."""
    import os
    mschap_lines, seen_m = [], set()
    md5_lines, seen_d = [], set()
    for sess in collector.sessions.values():
        for cred in sess.mschap_creds:
            line = build_5500_mschapv2(cred["username"], None,
                                       cred["peer_challenge"],
                                       cred["auth_challenge"],
                                       cred["nt_response"])
            if line and line not in seen_m:
                seen_m.add(line); mschap_lines.append(line)
        for cred in sess.md5_creds:
            line = build_4800_md5chap(cred["identifier"], cred["challenge"],
                                      cred["response"])
            if line and line not in seen_d:
                seen_d.add(line); md5_lines.append(line)

    written = {}
    if mschap_lines:
        p = os.path.join(output_dir, f"{base}-mschapv2.5500")
        with open(p, "w") as f:
            f.write("\n".join(mschap_lines) + "\n")
        written["5500"] = (p, len(mschap_lines))
    if md5_lines:
        p = os.path.join(output_dir, f"{base}-eapmd5.4800")
        with open(p, "w") as f:
            f.write("\n".join(md5_lines) + "\n")
        written["4800"] = (p, len(md5_lines))
    return written


# ---------------------------------------------------------------------
# Capture scanning — dependency-injected so this module doesn't need to
# duplicate Wiforge's own radiotap/802.11/fragmentation parsing.
# ---------------------------------------------------------------------

def scan_enterprise_capture(path, open_reader, parse_radiotap,
                            parse_80211_header, make_fragbuffer,
                            ft_data, show_progress=True,
                            progress_cls=None):
    """Re-scan a capture end to end collecting every EAP packet into an
    EnterpriseCollector. The five parser arguments are Wiforge's own
    open_reader/parse_radiotap/parse_80211_header/FragBuffer/FT_DATA —
    passed in so this module has no import-time dependency on the main
    (hyphenated-filename) script."""
    collector = EnterpriseCollector()
    reader = open_reader(path)
    fragbuf = make_fragbuffer()
    progress = None
    if progress_cls is not None:
        progress = progress_cls(0, prefix="Scanning (EAP)", enable=show_progress)
        try:
            import os
            progress.total = max(os.path.getsize(path) // 200, 1000)
        except Exception:
            progress.total = 1000
    try:
        for linktype, ts, pkt in reader:
            if progress:
                progress.update(1)
            rt = parse_radiotap(pkt)
            pkt2 = rt["body"]
            h = parse_80211_header(pkt2)
            if h is None or h["ftype"] != ft_data or h["protected"]:
                continue
            body = pkt2[h["hdr_len"]:]
            body = fragbuf.push(h, body)
            if body is None:
                continue
            if len(body) < 8 or body[0:3] != b"\xaa\xaa\x03":
                continue
            ethertype = struct.unpack_from(">H", body, 6)[0]
            if ethertype != 0x888E:
                continue
            eapol = body[8:]
            if h["to_ds"] and not h["from_ds"]:
                bssid, sta = h["addr1"], h["addr2"]
            elif h["from_ds"] and not h["to_ds"]:
                bssid, sta = h["addr2"], h["addr1"]
            else:
                bssid, sta = h["addr3"], h["addr2"]
            bssid_hex = bytes(bssid).hex()
            sta_hex = bytes(sta).hex()
            collector.feed(bssid_hex, sta_hex, eapol)
    finally:
        reader.close()
        if progress:
            progress.close()
    return collector


def report_enterprise_creds(collector, printer):
    """printer: a callable like print(), or Wiforge's colored print — kept
    generic so this module stays presentation-agnostic. Returns True if
    anything crackable was found."""
    found_any = False
    for (bssid_hex, sta_hex), sess in collector.sessions.items():
        type_names = {1: "Identity", 4: "MD5-Challenge", 13: "TLS",
                     21: "TTLS", 25: "PEAP", 26: "MSCHAPv2"}
        seen = ", ".join(type_names.get(t, f"type{t}") for t in
                         sorted(sess.eap_types_seen))
        printer(f"  BSSID={bssid_hex} STA={sta_hex}  EAP seen: {seen}")
        if sess.identity:
            printer(f"    Identity          : {sess.identity}")
        if sess.saw_tunnel and not sess.mschap_creds and not sess.md5_creds:
            printer("    (PEAP/TTLS/TLS tunnel seen — inner credentials "
                    "are encrypted and not recoverable from this capture "
                    "unless it's an already-decrypted/relayed session)")
        for cred in sess.mschap_creds:
            found_any = True
            printer(f"    MSCHAPv2 creds    : user={cred['username']!r} "
                    f"(AuthChallenge={cred['auth_challenge'].hex()}, "
                    f"PeerChallenge={cred['peer_challenge'].hex()})")
        for cred in sess.md5_creds:
            found_any = True
            printer(f"    EAP-MD5 creds     : user={cred['username']!r} "
                    f"id={cred['identifier']:02x} "
                    f"challenge={cred['challenge'].hex()}")
    return found_any
