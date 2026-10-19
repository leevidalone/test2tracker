#!/usr/bin/env python3
"""
aion2_reader.py - passive, read-only live reader for Odyle Energy / Charged Energy.

It only LISTENS to the game's network traffic on your own PC (same method as the
probe). It never sends, changes or injects anything and never touches the game.

Live (run as Administrator, ExitLag OFF, game running):
    aion2_reader.exe                      (double-click, or:)
    python aion2_reader.py live --proc Aion2.exe

Offline test against a probe capture:
    python aion2_reader.py file test6.jsonl

What it prints: every time the game sends the current character's energy and/or
charged energy (login, swapping characters, spending/gaining energy).
It also keeps the latest values in aion2_reader_state.json next to the program.
"""
import argparse, collections, json, re, struct, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:  # explicit imports so PyInstaller bundles these
    import psutil  # noqa: F401
    import scapy.all  # noqa: F401
except ImportError:
    pass

TAG = b"\x87\x93\x03"     # field tag that precedes the resource values
PORT = 13328              # game server port seen in captures
STATE_FILE = "aion2_reader_state.json"
HTTP_PORT = 17520          # local page <-> reader link (127.0.0.1 only)
CLASS_FILE = "aion2_reader_classes.json"
CLASS_ICONS = {
    "Spiritmaster": "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",
    "Cleric": "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",
    "Chanter": "iVBORw0KGgoAAAANSUhEUgAAABwAAAAcCAYAAAByDd+UAAAGh0lEQVR42t1Wa0xb5xl+v3Nsg6+Abwd8wYqxDbEdiDElITeyXLamXdoKYiOittlyYV0iSBOxqSudbFiIVLVrlkjtjygdzVjJcNS0TduElGbgwZabVBIKKzDAgXjY5mZisI2xfb79KGitEiiJ1j97f50fr97nPO/lex6AxwiMMcIYI/g/jG+YrVhhpAyGPCVCCH5Qphg7SACAGzeunL3+j49b5ttLAMCyQYllzIsEAORwOEiErPG6M8eKIT5VzOXE1zn+8mY5QoheYDmfu2Qwvi8BIRRf+D558mSCQi48crau0SEQJAWeK955dM+ePfUAEPh2LsYYIYTwchkihBCkp6ennTlz+o9tbc63cnJUyVarNd7ScpE37PYnPbfrhZwdz1g2I4LLlskEMoQQDQDspksf2c6eO9OoWKvQAACAzfZA/Ye2wGKxkCwWKzQ0NEzuP7DvrfVrN7HvByZcRytfrUhkc/KDoYg/MBMM8di8VGGKlKfO0HsqKl4q2bh5/fH36xvevXqh5YrNZgNndTW9rBlaLBZwOp0xk8mU5Xa74zKFfFU0GucJk4UHMU1HzzWev93edr171OfzK5TKslAoKFSrVxhGfaO0RCzNBIDYYiN6gKHNZiPKy8vp2lqbftcu69s8Ho/R1fXV1Jt/+P11dgIrIKWolTmmXI1YmKKKRmZxb9+/Ltnt1XcK1q17SqGUyTVajSHX9MSNysrKQYwxUV1djZdiiOx2O2CMOea8/HfkijRqYmI80NvXM11RcdhQW/tGVX//QBOLSRLClBQiMBPsOvzyr8qPHKnUeD2emM836pdKxPysLM3bfD5f9M3+fPdOvwPocDgIhBB96FDZPr1hZeHUlD+QyE5IzjXnCfv7+7v2/+LnP93+kx+nA9A0EBgbs7PFVVWvPNvVdcdlNueSIqFI6vdPTq4yGLLKDx2snN/URQFRSUlJ3Gw2c3SZmc8mMBPisViMCRgFvvi8+Wh+fsHshvUba5hM5tbRsTHP+OT4BF+QvNpozD6+bds2TmPjucrgTHCQxsCL03RMp9PuMBqN1PwGowcAbTYbwhiDRqNJIwhGMpPFxJFIhDx9+t0dnZ3/HPJ6vDUvlR3cfuvmrZcJQMJQMCzo7es9VVq62+Tz+X6ZlCQWvP76scLoXDSYmJAABElydDqdZqH2oltKUZSQQGhcwBcwvL6xv506dWpsw8aC43Ph2cmioqJdTZeaNFqNNjnPnCe/+MnFlNIXSl8MhoMeSka9erX9Gtf975FPuPwUBsEgvFKpVLDoWdjtdgAAUCpXcGMx2heYnp7xeTyisgP7G9Io2Y8oCaUCksjM0GbISJKBAKF4VmaWkqZptVgi0inkCtPzJbsbXK7hjEgkEg3ORD06XQ4XAMBgMKAlANNm4xjgrmvwNiWhNKHpUNtAj6syZ7VZZsrO/UwhU7ZRUkokpVKTNBm6Xr1ef37Lli1Kr8/7uxG394JGrdV4vZ4eABRWKmXRpRhiAIC+vr6JJ1br1374wYWr8Xgktv3JQr65wDja29fZsGaNwZGWmrK36cqnt5ytzV/y+cz1z+x86ot7w+7PtSptr9Vq5fH5fE5Dw7mPCws3FESjwWkAgO7ubvywwyecTieWSYUmvVH7YpIgUdF89cpXXC63sL9/cCsdC/vHJ723WSyWhMUiJBw2k89kJUaHXMPNHrcnPuLzHuDxePkdHbfvGAyGlXK5XH358uW/tre3d7W2tqKFB+BhOoZUKg5VVWX/tXdkdA2DwZKFAsGeoaGhgWRe4qerc/UbpanistBsNDo1dv8jr8/f6J2YKBJKpOlqldY06Z8eUaTLvz5x4sSxmzdv3kUIYYz/+9gsKZylRUVZ3OSEouxVWU/r1RSThaPZMQzRyTH/8GxklhakCCVpMlUSmcjtudPrCl+71uEMhyOO+vr6jm/Vx9+rFguCa6upGfuyo6uNZMZ4ylRxEZ8B9wNT0+HBgSH/THCGFotELDaLDLvdo6mXmls/qHvvz7/p7Oz0LrgAp9OJlyvA2Gq1xi0WC2mxWKC7++9/mpuLqa51ujYxmWQCm8dnEwwm0XfXM9359b05kUjcpNbI3sEYE3b7ZgIhtKhaPJIBKi7easrJ0tdymaQc6Hg4DDg6cM/3Wl3deediLXzcQC0220I3+K+9cthR89ujzVKplAIAaGmxMR7155cVhYWFDAQAe/fu3rTvZ8/vnBdr1g9tTtGjuL7/kT99fKv/Hwoez4y4K+QdAAAAAElFTkSuQmCC",
    "Gladiator": "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",
    "Sorcerer": "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",
    "Templar": "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",
    "Assassin": "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",
    "Ranger": "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",
}

ALLOWED_ORIGINS = ["https://leevidalone.github.io", "http://localhost", "http://127.0.0.1"]


# ---------------------------------------------------------------- decoding ---
def lz4_block(src, want):
    """LZ4 block decoder that stops once `want` bytes are produced."""
    out = bytearray()
    i, n = 0, len(src)
    while i < n and len(out) < want:
        tok = src[i]; i += 1
        lit = tok >> 4
        if lit == 15:
            while True:
                b = src[i]; i += 1; lit += b
                if b != 255:
                    break
        out += src[i:i + lit]; i += lit
        if len(out) >= want or i >= n:
            break
        off = src[i] | (src[i + 1] << 8); i += 2
        if off == 0 or off > len(out):
            raise ValueError("bad offset")
        ml = tok & 15
        if ml == 15:
            while True:
                b = src[i]; i += 1; ml += b
                if b != 255:
                    break
        ml += 4
        for _ in range(ml):
            out.append(out[-off])
    if len(out) != want:
        raise ValueError("size mismatch")
    return bytes(out)


def varint(d, p):
    v = sh = 0
    while p < len(d):
        c = d[p]; p += 1
        v |= (c & 0x7F) << sh
        sh += 7
        if not c & 0x80:
            return v, p
        if sh > 35:
            break
    return None, p


def scan_resources(d):
    """Yield (energy|None, charged|None) found in a block of decoded bytes.
    Layout: ... [flags] 01 87 93 03 [energy varint if flags&4] [charged varint if flags&8]"""
    out = []
    j = d.find(TAG)
    while j != -1:
        if j >= 2 and d[j - 1] == 0x01 and d[j - 2] in (0x04, 0x08, 0x0C):
            fl = d[j - 2]
            p = j + 3
            e = c = None
            ok = True
            if fl & 0x04:
                e, p = varint(d, p)
                ok = e is not None
            if ok and fl & 0x08:
                c, p = varint(d, p)
                ok = c is not None
            if ok and p + 2 > len(d):
                ok = False            # message cut off here; classify it once more data arrives
            if ok and (e is None or e <= 100000) and (c is None or c <= 100000):
                out.append((j, e, c, d[p:p + 2] == b"\x04\x02"))
        j = d.find(TAG, j + 1)
    return out


NAME_RE = re.compile(rb"\x37([\x02-\x18])")


def scan_names(d):
    """Return [(offset, name, server_id)] for the current-character marker:
    .. .. .. 37 [len][name] [server id u16 LE] [level u32 LE]
    (the bytes before the 37 vary between characters)."""
    out = []
    for m in NAME_RE.finditer(d):
        n = m.group(1)[0]
        p = m.end()
        raw = d[p:p + n]
        tail = d[p + n:p + n + 6]
        # server id (u16) is followed by a small u32 whose top three bytes are zero
        if len(raw) == n and len(tail) == 6 and tail[3:6] == b"\x00\x00\x00":
            sid = tail[0] | (tail[1] << 8)
            if not (1 <= sid <= 20000):
                continue
            try:
                nm = raw.decode("utf-8")
            except UnicodeDecodeError:
                continue
            if nm.isalnum():          # character names are letters and digits only
                out.append((m.start(), nm, sid))
    return out


ASC_RE = re.compile(rb"([\x04\x0c])\x01\xb4\xc4\x04")


def scan_asc(d, j):
    """Ascension Trial entries in a swap/login dump, found after the energy block at j:
    [flags 04|0c] 01 b4 c4 04 [entries left] [extra if flags&8].  Returns (left, extra) or None."""
    m = ASC_RE.search(d, j, j + 1500)
    if not m:
        return None
    left, p = varint(d, m.end())
    if left is None or left > 3:
        return None
    extra = 0
    if m.group(1)[0] & 0x08:
        extra, p = varint(d, p)
        if extra is None or extra > 1000:
            return None
    return (left, extra)


NM_HDR = b"\x80\x85\x80\x01\x00\x00\x00\x00"


def scan_nm(d, j):
    """Nightmare tickets in a swap/login dump (energy block at j).  The game sends a table of
    counters before it: header 80 85 80 01 00 00 00 00, then entries
    [flags 00|04|08|0c] [id u32 LE] [value if flags&4] [extra if flags&8].
    Entry id 4 is the Nightmare tickets (current, extra); no entry means 0.
    Returns (tickets, extra) or None if the table is not found."""
    h = d.find(NM_HDR, max(0, j - 3000), j)
    if h < 0:
        return None
    p = h + 8
    for _ in range(40):
        if p + 5 > len(d):
            return None
        fl = d[p]
        if fl not in (0, 4, 8, 12):
            break
        eid = int.from_bytes(d[p + 1:p + 5], "little")
        q = p + 5
        v1 = v2 = None
        if fl & 4:
            v1, q = varint(d, q)
        if fl & 8:
            v2, q = varint(d, q)
        if eid == 4:
            if (fl & 4 and v1 is None) or (fl & 8 and v2 is None):
                return None
            if (v1 or 0) > 14 or (v2 or 0) > 100:
                return None
            return (v1 or 0, v2 or 0)
        p = q
    return (0, 0)


UPD_ASC_RE = re.compile(rb"([\x00\x04\x08\x0c])\x01\xb4\xc4\x04")


def scan_asc_updates(d):
    """Live Ascension Trial updates (e.g. an entry is spent):
    .. 61 00 [flags 00|04|08|0c] 01 b4 c4 04 [entries left if flags&4] [extra if flags&8]
    This is the whole entry: a field that is left out is 0.  Returns [(offset, left, extra)]."""
    out = []
    for m in UPD_ASC_RE.finditer(d):
        s = m.start()
        if s < 2 or d[s - 2:s] != b"\x61\x00":
            continue                      # (a full dump has its own layout, read by scan_asc)
        fl = m.group(1)[0]
        p = m.end()
        left = extra = 0
        if fl & 0x04:
            left, p = varint(d, p)
            if left is None or left > 3:
                continue
        if fl & 0x08:
            extra, p = varint(d, p)
            if extra is None or extra > 1000:
                continue
        out.append((s, left, extra))
    return out


UPD_NM_RE = re.compile(rb"\x61\x00([\x00\x04\x08\x0c])\x04\x00\x00\x00")


def scan_nm_updates(d):
    """Live Nightmare ticket updates (a ticket is used):
    .. 61 00 [flags 00|04|08|0c] 04 00 00 00 [tickets if flags&4] [extra if flags&8]
    This is the whole entry: a field that is left out is 0 (flags 00 = 0 tickets, no extra).
    Returns [(offset, tickets, extra)]."""
    out = []
    for m in UPD_NM_RE.finditer(d):
        fl = m.group(1)[0]
        p = m.end()
        left = extra = 0
        if fl & 0x04:
            left, p = varint(d, p)
            if left is None or left > 14:
                continue
        if fl & 0x08:
            extra, p = varint(d, p)
            if extra is None or extra > 100:
                continue
        out.append((m.start(), left, extra))
    return out


def find_bundles(buf, start=0):
    """Find compressed bundles: [varint len][ff ff][u32 size][lz4 ...].
    Returns ([(offset_of_ff, end_offset, decoded)], resume_offset)."""
    res = []
    i = start
    resume = len(buf)
    while True:
        i = buf.find(b"\xff\xff", i)
        if i == -1 or i + 6 > len(buf):
            break
        size = struct.unpack("<I", buf[i + 2:i + 6])[0]
        got = None
        if 0 < size < (1 << 18):
            for back in (1, 2, 3):
                if i - back < 0:
                    continue
                L, q = varint(buf, i - back)
                if L is None or q != i:
                    continue
                if L > (1 << 17):
                    continue
                if i + L > len(buf):
                    got = "wait"          # frame not fully received yet
                    break
                try:
                    got = (i, i + L, lz4_block(buf[i + 6:i + L], size))
                    break
                except Exception:
                    pass
        if isinstance(got, tuple):
            res.append(got)
            i = got[0] + 2            # next frame can start before this one's estimated end
        elif got == "wait":
            resume = max(0, i - 3)
            break
        else:
            i += 1
    return res, resume


class Stream:
    """Reassembles one inbound TCP stream and reports resource messages once each."""

    def __init__(self, on_value, on_name=None, on_asc=None, on_nm=None):
        self.segs = {}
        self.next = None
        self.buf = bytearray()
        self.base = 0              # absolute offset of buf[0]
        self.seen = set()
        self.scanned = 0           # absolute offset scanned up to (for raw tags)
        self.on_value = on_value
        self.on_name = on_name
        self.on_asc = on_asc
        self.on_nm = on_nm
        self.gap_since = None
        self.bytes_in = 0
        self.resyncs = 0
        self.bundles = 0

    def feed(self, seq, data, now=None):
        now = time.monotonic() if now is None else now
        if len(data) <= 6 and not any(data):
            return                    # Ethernet padding on empty ACK packets, not game data
        self.bytes_in += len(data)
        if self.next is None:
            self.next = seq
        if seq < self.next:
            if seq + len(data) <= self.next:
                return
            data = data[self.next - seq:]
            seq = self.next
        self.segs[seq] = data
        self.drain()
        if self.segs:
            # a packet is missing (the sniffer can drop one). Wait briefly, then skip it
            # so the stream never stays stuck.
            if self.gap_since is None:
                self.gap_since = now
            pending = sum(len(v) for v in self.segs.values())
            if now - self.gap_since > 0.7 or pending > 100000:
                self.next = min(self.segs)
                self.resyncs += 1
                self.gap_since = None
                self.drain()
        else:
            self.gap_since = None
        self.process()

    def drain(self):
        while self.next in self.segs:
            d = self.segs.pop(self.next)
            self.buf += d
            self.next += len(d)
        # drop segments that are now entirely behind us
        for k in [k for k in self.segs if k + len(self.segs[k]) <= self.next]:
            del self.segs[k]

    def process(self):
        b = bytes(self.buf)
        start = max(0, self.scanned - self.base - 16)
        bundles, resume = find_bundles(b, start)
        spans = [(off - 3, end) for off, end, _ in bundles]
        ev = []                                     # (position, kind, data)

        def outside(j):                             # plain message, not inside a compressed bundle
            return j < resume and not any(a <= j < e for a, e in spans)

        hold = None
        for j, e, c, dump in scan_resources(b[start:]):
            P = start + j
            if outside(P):
                asc = None
                if dump:                  # a plain (not compressed) dump: Ascension follows ~165 bytes later
                    if len(b) - P < 400:
                        hold = P if hold is None else min(hold, P)
                        continue          # wait for the rest of the frame
                    asc = scan_asc(b[:P + 400], P)
                ev.append((P, "val", (e, c, "plain", dump, asc, None)))
        for j, nm, sid in scan_names(b[start:]):
            if outside(start + j):
                ev.append((start + j, "name", (nm, sid)))
        for j, left, extra in scan_asc_updates(b[start:]):
            if outside(start + j):
                ev.append((start + j, "asc", (left, extra)))
        for j, left, extra in scan_nm_updates(b[start:]):
            if outside(start + j):
                ev.append((start + j, "nmu", (left, extra)))
        for off, end, dec in bundles:
            for j, left, extra in scan_nm_updates(dec):
                ev.append((off + j / 1e6, "nmu", (left, extra)))
            for j, left, extra in scan_asc_updates(dec):
                ev.append((off + j / 1e6, "asc", (left, extra)))
            for j, e, c, dump in scan_resources(dec):
                ev.append((off + j / 1e6, "val", (e, c, "bundle", dump,
                                                  scan_asc(dec, j) if dump else None,
                                                  scan_nm(dec, j) if dump else None)))
            for j, nm, sid in scan_names(dec):
                ev.append((off + j / 1e6, "name", (nm, sid)))
        ev.sort(key=lambda x: x[0])
        for pos, kind, data in ev:
            key = (kind, self.base + pos)
            if key in self.seen:
                continue
            self.seen.add(key)
            if kind == "val":
                self.on_value(*data)
            elif kind == "asc":
                if self.on_asc:
                    self.on_asc(*data)
            elif kind == "nmu":
                if self.on_nm:
                    self.on_nm(*data)
            elif self.on_name:
                self.on_name(*data)
        for off, end, dec in bundles:
            k = ("bun", self.base + off)
            if k not in self.seen:
                self.seen.add(k)
                self.bundles += 1
        if hold is not None:
            resume = min(resume, max(0, hold - 1))
        self.scanned = self.base + resume
        # keep memory bounded
        if len(self.buf) > 600000:
            cut = len(self.buf) - 200000
            del self.buf[:cut]
            self.base += cut
            self.seen = {k for k in self.seen if k[1] >= self.base}


class State:
    """Pairs energy messages with the character name that arrives with a swap/login."""
    WINDOW = 12.0         # seconds to wait for the other half of a swap/login

    def __init__(self):
        self.clock = time.time()
        self.name = None
        self.last_name = None     # character of the last full swap/login seen
        self.name_t = 0.0
        self.sid = None
        self.energy = 0
        self.charged = 0
        self.chars = {}
        self.pend_vals = None     # (e, c, how, t) waiting for a name
        self.pend_name = None     # (name, t) waiting for values
        self.lock = threading.Lock()
        self.seq = 0
        self.classes = {}
        try:
            with open(CLASS_FILE) as f:
                self.classes = {str(k): str(v) for k, v in json.load(f).items() if str(v) in CLASS_ICONS}
        except Exception:
            pass

    def set_classes(self, m):
        """Class of each character, sent by the tracker page (the reader cannot read it from the game)."""
        ok = {str(k)[:40]: str(v) for k, v in list(m.items())[:200] if str(v) in CLASS_ICONS}
        with self.lock:
            if ok == self.classes:
                return
            self.classes = ok
        try:
            with open(CLASS_FILE, "w") as f:
                json.dump(ok, f)
        except Exception:
            pass

    # events from the stream decoder
    def on_value(self, e, c, how, dump=False, asc=None, nm=None):
        t = self.clock
        if not dump:                      # a plain update (spent / gained energy)
            self.emit(e, c, how, swap=False)
        elif self.pend_name and t - self.pend_name[1] <= self.WINDOW:
            self.name, self.sid = self.pend_name[0], self.pend_name[2]   # a real dump confirms the name
            self.name_t = t
            self.pend_name = None
            self.emit(e, c, how, swap=True, asc=asc, nm=nm)
        else:                             # swap/login dump: wait for the name
            self.pend_vals = (e, c, how, t, asc, nm)

    def on_name(self, nm, sid=None):
        t = self.clock
        if self.pend_name and nm == self.pend_name[0] and t - self.pend_name[1] < 3.0:
            return                    # same marker repeated within one swap
        if nm == self.name and t - self.name_t < 3.0:
            return
        # A name marker alone proves nothing: other players' names (party, guild, people nearby)
        # carry the same marker. It only becomes the current character when a swap/login dump
        # (energy values) arrives with it.
        if self.pend_vals and t - self.pend_vals[3] <= self.WINDOW:
            e, c, how, _, asc, nmv = self.pend_vals
            self.pend_vals = None
            self.name, self.sid, self.name_t = nm, sid, t
            self.emit(e, c, how, swap=True, asc=asc, nm=nmv)
        else:
            self.pend_name = (nm, t, sid)

    def tick(self, now=None):
        """Flush anything that has waited long enough."""
        t = self.clock if now is None else now
        if self.pend_vals and t - self.pend_vals[3] > self.WINDOW:
            e, c, how, _, asc, nmv = self.pend_vals
            self.pend_vals = None
            self.emit(e, c, how, swap=True, asc=asc, nm=nmv)   # a full dump even though no name came
        if self.pend_name and t - self.pend_name[1] > self.WINDOW:
            self.pend_name = None     # a name with no energy values: not a character swap, ignore it

    def _adopt(self):
        """Ascension/Nightmare values arriving right after a name marker belong to that swap."""
        if self.pend_name and self.clock - self.pend_name[1] <= 3.0:
            self.name, self.sid, self.name_t = self.pend_name[0], self.pend_name[2], self.clock
            self.last_name = self.name
            self.pend_name = None

    def on_asc(self, left, extra):
        """Live Ascension update for the current character (an entry was spent / gained)."""
        self._adopt()
        if not self.name:
            return
        with self.lock:
            self.seq += 1
            rec = self.chars.setdefault(self.name, {})
            if left is not None:
                rec["asc"] = left
            if extra is not None:
                rec["ascExtra"] = extra
            rec["ascUpdated"] = time.time()
            if self.sid:
                rec["serverId"] = self.sid
            l, x = rec.get("asc"), rec.get("ascExtra", 0)
        print("[%s] %-14s ascension %s (+%s)  (update)" % (
            time.strftime("%H:%M:%S"), self.name, "?" if l is None else l, x))
        try:
            with open(STATE_FILE, "w") as f:
                json.dump(self.snapshot(), f, indent=1)
        except Exception:
            pass

    def on_nm(self, left, extra):
        """Live Nightmare ticket update for the current character (a ticket was used)."""
        self._adopt()
        if not self.name:
            return
        with self.lock:
            self.seq += 1
            rec = self.chars.setdefault(self.name, {})
            if left is not None:
                rec["nm"] = left
            if extra is not None:
                rec["nmExtra"] = extra
            rec["nmUpdated"] = time.time()
            if self.sid:
                rec["serverId"] = self.sid
            l, x = rec.get("nm"), rec.get("nmExtra", 0)
        print("[%s] %-14s nightmare %s (+%s)  (update)" % (
            time.strftime("%H:%M:%S"), self.name, "?" if l is None else l, x))
        try:
            with open(STATE_FILE, "w") as f:
                json.dump(self.snapshot(), f, indent=1)
        except Exception:
            pass

    def emit(self, e, c, how, swap, asc=None, nm=None):
        if swap:
            self.last_name = self.name
        if swap:               # a fresh character: fields the game leaves out are 0
            self.energy = e if e is not None else 0
            self.charged = c if c is not None else 0
        else:                  # an update: fields left out are unchanged
            if e is not None:
                self.energy = e
            if c is not None:
                self.charged = c
        who = self.name or "?"
        with self.lock:
            self.seq += 1
            if self.name:
                self.chars.setdefault(self.name, {}).update(
                    {"energy": self.energy, "charged": self.charged, "updated": time.time()})
                if self.sid:
                    self.chars[self.name]["serverId"] = self.sid
                if asc is not None:
                    self.chars[self.name]["asc"] = asc[0]
                    self.chars[self.name]["ascExtra"] = asc[1]
                    self.chars[self.name]["ascUpdated"] = time.time()
                if nm is not None:
                    self.chars[self.name]["nm"] = nm[0]
                    self.chars[self.name]["nmExtra"] = nm[1]
                    self.chars[self.name]["nmUpdated"] = time.time()
        print("[%s] %-14s energy %-5s | charged energy %-5s%s  (%s%s)" % (
            time.strftime("%H:%M:%S"), who, self.energy, self.charged,
            ("" if asc is None else " | ascension %d (+%d)" % asc) +
            ("" if nm is None else " | nightmare %d (+%d)" % nm),
            "swap/login" if swap else "update", ", " + how if how == "no values sent" else ""))
        try:
            with open(STATE_FILE, "w") as f:
                json.dump(self.snapshot(), f, indent=1)
        except Exception:
            pass

    def snapshot(self):
        with self.lock:
            return {"app": "aion2_reader", "version": 1, "seq": self.seq,
                    "current": self.name, "energy": self.energy,
                    "charged": self.charged,
                    "characters": json.loads(json.dumps(self.chars)),
                    "classes": dict(self.classes),
                    "now": time.time()}



# ------------------------------------------------------------ local server ---
def origin_ok(origin, extra):
    if not origin:
        return False
    for o in ALLOWED_ORIGINS + list(extra):
        if origin == o or origin.startswith(o + ":"):   # allow any port on localhost/127.0.0.1
            return True
    return False


def start_server(state, port=HTTP_PORT, extra=()):
    """Serve the latest values to the tracker page. Bound to 127.0.0.1 only; replies only to
    the allowed web page origins. It accepts nothing except the class names (POST /classes)."""
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _cors(self):
            origin = self.headers.get("Origin", "")
            if origin_ok(origin, extra):
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Vary", "Origin")
                self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
                self.send_header("Access-Control-Allow-Headers", "*")
                if self.headers.get("Access-Control-Request-Private-Network"):
                    self.send_header("Access-Control-Allow-Private-Network", "true")
                self.send_header("Access-Control-Max-Age", "600")

        def do_OPTIONS(self):
            self.send_response(204)
            self._cors()
            self.end_headers()

        def do_POST(self):
            # the only thing accepted: the class names the tracker page knows for each character
            ok = False
            try:
                n = int(self.headers.get("Content-Length", "0"))
                if self.path.split("?")[0] == "/classes" and 0 < n <= 20000 and origin_ok(self.headers.get("Origin", ""), extra):
                    m = json.loads(self.rfile.read(n))
                    if isinstance(m, dict):
                        state.set_classes(m)
                        ok = True
            except Exception:
                pass
            self.send_response(204 if ok else 400)
            self._cors()
            self.end_headers()

        def do_GET(self):
            path = self.path.split("?")[0]
            if path == "/state":
                body = json.dumps(state.snapshot()).encode()
                ctype = "application/json"
            elif path in ("/", "/ping"):
                body = b"aion2_reader is running"
                ctype = "text/plain"
            else:
                self.send_response(404)
                self._cors()
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Cache-Control", "no-store")
            self._cors()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    try:
        httpd = ThreadingHTTPServer(("127.0.0.1", port), H)
    except OSError as e:
        print("Could not start the local link on port %d (%s). Is another reader already running?" % (port, e))
        return None
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    print("Tracker link ready on http://127.0.0.1:%d (only this PC can reach it)" % port)
    return httpd

# ------------------------------------------------------------------- modes ---
def cmd_file(a):
    st = State()
    streams = {}
    n = 0
    for line in open(a.file):
        r = json.loads(line)
        if r["dir"] != "in" or not r["flow"].startswith("tcp") or not r["flow"].endswith(":%d" % a.port):
            continue
        s = streams.setdefault(r["flow"], Stream(st.on_value, st.on_name, st.on_asc, st.on_nm))
        st.clock = r["t"]
        st.tick()
        s.feed(r["seq"], bytes.fromhex(r["hex"]), r["t"])
        n += 1
    st.tick(st.clock + 10)
    print("Done (%d inbound packets)." % n)
    if getattr(a, "serve", False):
        start_server(st, getattr(a, "port_http", HTTP_PORT), getattr(a, "origin", []) or [])
        print("Serving the replayed values. Ctrl+C to stop.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass


def is_loop(ip):
    return ip.startswith("127.") or ip in ("::1", "0.0.0.0", "::")


def game_flows(proc):
    import psutil
    pids = {p.pid for p in psutil.process_iter(["name"])
            if (p.info["name"] or "").lower() == proc.lower()}
    out = set()
    for c in psutil.net_connections(kind="inet"):
        if c.pid in pids and c.type == 1 and c.raddr and c.status == "ESTABLISHED" \
                and not is_loop(c.raddr.ip) and c.raddr.port != 443:
            out.add((c.laddr.port, c.raddr.ip, c.raddr.port))
    return out


class FlowPicker:
    """Finds the game stream by its content when it can't be matched to the game program
    (ExitLag or another VPN/booster carries the game data under its own connection).
    ExitLag can send the same data down several routes, so use one route at a time.
    Recent data of every candidate flow is kept briefly so nothing is lost when one is chosen."""
    KEEP = 768 * 1024
    MAXKEYS = 24

    def __init__(self):
        self.score = {}
        self.check = {}
        self.hold = collections.OrderedDict()
        self.active = None
        self.last = 0.0
        self.changed = False
        self.good = set()
        self.save_out = []

    def route(self, key, seq, payload, now):
        """Return the (seq, payload, time) pieces to feed to the stream for this flow."""
        self.changed = False
        if key in self.good:
            self.save_out.append((key, seq, payload, now))
        if self.active == key:
            self.last = now
            return [(seq, payload, now)]
        if self.active is not None and now - self.last > 4:
            self.active = None
        h = self.hold.get(key)
        if h is None:
            if len(self.hold) >= self.MAXKEYS:
                old = next((k for k in self.hold if k not in self.good and k != self.active), None)
                if old is None:
                    old = next(iter(self.hold))
                del self.hold[old]
                self.score.pop(old, None)
                self.check.pop(old, None)
                self.good.discard(old)
            h = self.hold[key] = [0, []]
        else:
            self.hold.move_to_end(key)
        h[1].append((seq, payload, now))
        h[0] += len(payload)
        while h[0] > self.KEEP and len(h[1]) > 1:
            h[0] -= len(h[1].pop(0)[1])
        self.score[key] = sc = self.score.get(key, 0) + payload.count(TAG)
        if sc < 2 and b"\xff\xff" in payload:
            nxt = self.check.get(key, 4096)       # look for real compressed bundles now and then
            if h[0] >= nxt and nxt <= 262144:
                self.check[key] = nxt * 4
                try:
                    buf = b"".join(p[1] for p in sorted(h[1], key=lambda p: p[0]))
                    sc += len(find_bundles(buf)[0])
                except Exception:
                    pass
        if sc >= 2 and key not in self.good:
            self.good.add(key)                    # a game stream (maybe one of several ExitLag routes)
            for sq, pl, ts in h[1]:
                self.save_out.append((key, sq, pl, ts))
        if self.active is None and sc >= 2:
            self.active = key
            self.last = now
            self.changed = True
            out = h[1]
            h[1] = []
            h[0] = 0
            return out
        return []


def local_ips():
    import psutil
    out = set()
    for addrs in psutil.net_if_addrs().values():
        for a in addrs:
            if getattr(a, "family", None) is not None and a.family.name == "AF_INET":
                out.add(a.address)
    return out


LIVE = {}          # objects shared with the window (see gui_main)


def cmd_live(a):
    from scapy.all import sniff, TCP, IP
    st = State()
    start_server(st, getattr(a, "port_http", HTTP_PORT), getattr(a, "origin", []) or [])
    streams = {}
    flows = set()
    stop = threading.Event()
    picker = FlowPicker()
    mine = set()
    savef = open(a.save, "w", buffering=1) if getattr(a, "save", None) else None
    LIVE.update(state=st, flows=flows, picker=picker, streams=streams)

    def save_rec(key, seq, payload, ts):
        if savef:
            savef.write(json.dumps({"t": ts, "dir": "in", "flow": "tcp-%s-%s:%s" % tuple(key), "seq": seq, "hex": payload.hex()}) + "\n")

    def refresh():
        while not stop.is_set():
            try:
                flows.clear(); flows.update(game_flows(a.proc))
                mine.update(local_ips())
            except Exception:
                pass
            time.sleep(2)
    threading.Thread(target=refresh, daemon=True).start()
    time.sleep(2.5)
    try:
        mine.update(local_ips())
    except Exception:
        pass
    if not flows and getattr(a, "wait", False):
        print("No direct game connection yet. Listening for the game (start it and log in).")
        print("This also works through ExitLag or a VPN: the game data is found by its content.\n")
    elif not flows:
        sys.exit("No game connection found for %s. Is the game running and logged in "
                 "(and ExitLag OFF)?" % a.proc)
    if flows:
        print("Watching game connection(s):", sorted(flows))
    print("Now swap characters / log in / spend energy. Ctrl+C to stop.\n")

    def on(pkt):
        if IP not in pkt or TCP not in pkt:
            return
        ip, t = pkt[IP], pkt[TCP]
        payload = bytes(t.payload)
        try:   # drop Ethernet padding: keep only what the IP header says is TCP payload
            payload = payload[:max(0, ip.len - ip.ihl * 4 - t.dataofs * 4)]
        except Exception:
            pass
        if not payload:
            return
        if not flows:
            if (mine and ip.dst not in mine) or is_loop(ip.src) or t.sport in (443, 80, 53, 123):
                return
            key = (t.dport, ip.src, t.sport)
            pieces = picker.route(key, t.seq, payload, time.time())
            if savef and picker.save_out:
                for kk, sq, pl, ts in picker.save_out:
                    save_rec(kk, sq, pl, ts)
            picker.save_out = []
            if not pieces:
                return
            if picker.changed:
                print("[%s] game data found from %s:%d (via ExitLag/VPN or proxy)" % (
                    time.strftime("%H:%M:%S"), ip.src, t.sport))
            s = streams.get(key)
            if s is None:
                s = streams[key] = Stream(st.on_value, st.on_name, st.on_asc, st.on_nm)
            for sq, pl, ts in pieces:
                st.clock = ts          # replay buffered data with its original timing
                s.feed(sq, pl)
            st.clock = time.time()
            return
        for lp, rip, rp in flows:
            if ip.src == rip and t.sport == rp and t.dport == lp:
                key = (lp, rip, rp)
                s = streams.get(key)
                if s is None:
                    s = streams[key] = Stream(st.on_value, st.on_name, st.on_asc, st.on_nm)
                st.clock = time.time()
                save_rec(key, t.seq, payload, st.clock)
                s.feed(t.seq, payload)
                return
    def status():
        n = 0
        while not stop.is_set():
            time.sleep(1)
            st.clock = time.time()
            st.tick()
            n += 1
            if n % 20:
                continue
            tot = sum(x.bytes_in for x in streams.values())
            rs = sum(x.resyncs for x in streams.values())
            bn = sum(x.bundles for x in streams.values())
            print("  ... alive: %d KB received, %d bundles decoded, %d skipped gaps, %d connection(s)"
                  % (tot // 1024, bn, rs, len(streams)))
    threading.Thread(target=status, daemon=True).start()
    try:
        try:
            from scapy.all import get_if_list
            names = [n for n in get_if_list() if "Loopback" not in n]
        except Exception:
            names = None
        try:
            if names:
                sniff(iface=names, filter="tcp", prn=on, store=False, timeout=getattr(a, "secs", None))
            else:
                sniff(filter="tcp", prn=on, store=False, timeout=getattr(a, "secs", None))
        except KeyboardInterrupt:
            raise
        except Exception:
            sniff(filter="tcp", prn=on, store=False, timeout=getattr(a, "secs", None))
    except KeyboardInterrupt:
        pass
    stop.set()


def cmd_diag(a):
    """Show where the game traffic goes (use with ExitLag / a VPN ON). Writes aion2_diag.txt"""
    import collections as C, io
    import psutil
    from scapy.all import sniff, get_if_list, conf, TCP, UDP, IP, Raw
    out = io.StringIO()

    def p(*x):
        line = " ".join(str(i) for i in x)
        print(line)
        out.write(line + "\n")
    p("== game connections (psutil) for", a.proc)
    pids = {x.pid for x in psutil.process_iter(["name"]) if (x.info["name"] or "").lower() == a.proc.lower()}
    p("pids:", sorted(pids))
    for c in psutil.net_connections(kind="inet"):
        if c.pid in pids:
            p("  ", "TCP" if c.type == 1 else "UDP", c.laddr, "->", c.raddr or "-", c.status)
    p("\n== network adapters seen by scapy")
    names = list(get_if_list())
    for n in names:
        try:
            ip = conf.ifaces[n].ip
        except Exception:
            ip = "?"
        p("  ", n, ip)
    p("\n== sniffing ALL adapters for %d s (play: swap characters, spend energy)..." % a.secs)
    stat = C.defaultdict(lambda: [0, 0, 0, 0])

    def on(pkt):
        if IP not in pkt:
            return
        ip = pkt[IP]
        if TCP in pkt:
            pr, sp, dp, pay = "TCP", pkt[TCP].sport, pkt[TCP].dport, bytes(pkt[TCP].payload)
        elif UDP in pkt:
            pr, sp, dp, pay = "UDP", pkt[UDP].sport, pkt[UDP].dport, bytes(pkt[UDP].payload)
        else:
            return
        k = (getattr(pkt, "sniffed_on", "?"), pr, "%s:%d" % (ip.src, sp), "%s:%d" % (ip.dst, dp))
        r = stat[k]
        r[0] += 1
        r[1] += len(pay)
        r[2] += pay.count(b"\xff\xff")
        r[3] += pay.count(TAG)
    try:
        sniff(iface=names, prn=on, store=False, timeout=a.secs)
    except Exception as e:
        p("sniff on all adapters failed (%s); trying default adapter" % e)
        sniff(prn=on, store=False, timeout=a.secs)
    p("\n== busiest flows: adapter, proto, from, to | packets, payload bytes, 'ff ff' marks, resource tag hits")
    for k, r in sorted(stat.items(), key=lambda kv: -kv[1][1])[:25]:
        p("  ", *k, "|", *r)
    open("aion2_diag.txt", "w").write(out.getvalue())
    p("\nSaved aion2_diag.txt next to the program. Send me that file.")


def npcap_ok():
    if not sys.platform.startswith("win"):
        return True
    import os
    root = os.environ.get("SystemRoot", r"C:\Windows")
    return any(os.path.exists(os.path.join(root, "System32", p))
               for p in ("Npcap", "wpcap.dll")) or os.path.exists(os.path.join(root, "SysWOW64", "wpcap.dll"))


def auto_live():
    print("=" * 56)
    print(" Aion 2 game reader - passive, does not change the game")
    print("=" * 56)
    print("Keep this window open while you play. Close it to stop.\n")
    if not npcap_ok():
        print("Npcap was not found on this PC. The reader needs it to see game traffic.")
        print("Install it from https://npcap.com/#download (tick 'WinPcap API-compatible")
        print("mode'), then start this program again.")
        return
    print("Step 1: turn on 'Game reader' on the tracker page.")
    print("Step 2: log in to Aion 2 (ExitLag / game VPN OFF).")
    print("Step 3: swap characters once; each one appears on the page.\n")
    try:
        cmd_live(argparse.Namespace(proc="Aion2.exe", wait=True))
    except SystemExit as e:
        print(e)
    except Exception as e:
        print("Error:", e)
        print("If this mentions permissions or Npcap, right-click the program and choose "
              "'Run as administrator'.")


def interactive():
    print("Aion 2 energy reader - passive listener (does not change the game)\n")
    print("1) Live reader (game running, ExitLag OFF)")
    print("2) Test on a saved capture file")
    print("3) Quit")
    c = input("> ").strip()
    try:
        if c == "1":
            proc = input("Game program name [Aion2.exe]: ").strip() or "Aion2.exe"
            cmd_live(argparse.Namespace(proc=proc))
        elif c == "2":
            fn = input("Capture file name (e.g. test6.jsonl): ").strip()
            cmd_file(argparse.Namespace(file=fn, port=PORT))
    except SystemExit as e:
        print(e)
    except Exception as e:
        print("Error:", e)


TRACKER_URL = "https://leevidalone.github.io/test2tracker/"


class _Out:
    """Replaces stdout/stderr in the window (and when built without a console)."""
    def __init__(self, q):
        self.q = q

    def write(self, text):
        if text:
            self.q.put(text)
            real = sys.__stdout__
            if real is not None:          # also show it in the console when there is one
                try:
                    real.write(text)
                    real.flush()
                except Exception:
                    pass

    def flush(self):
        pass


def is_admin():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return True               # not Windows, or cannot tell


def ago(t, now=None):
    if not t:
        return "-"
    d = max(0, int((now or time.time()) - t))
    if d < 60:
        return "%ds ago" % d
    if d < 3600:
        return "%dm ago" % (d // 60)
    return "%dh ago" % (d // 3600)


def status_of(live, snap, admin_ok, npcap, now=None):
    """(colour, headline, hint) for the window."""
    if not npcap:
        return ("red", "Npcap is missing",
                "Install Npcap from npcap.com (tick WinPcap API-compatible mode), then start this program again.")
    if not admin_ok:
        return ("red", "Needs administrator rights",
                "Close this window, then right-click the program and choose Run as administrator.")
    err = live.get("error")
    if err:
        return ("red", "Problem", err)
    pk = live.get("picker")
    fl = live.get("flows")
    if (pk and pk.active) or fl:
        last = max([c.get("updated", 0) for c in snap.get("characters", {}).values()] or [0])
        via = " (through ExitLag / VPN)" if (pk and pk.active and not fl) else ""
        hint = ("Last update %s. Swap characters in game to refresh the numbers." % ago(last, now)) if last else \
            "Connected. Swap characters once in game and each one appears here."
        return ("green", "Reading the game" + via, hint)
    return ("amber", "Waiting for the game", "Start Aion 2 and log in. This works with ExitLag or a VPN too.")


PALETTES = {      # same colours as the tracker page
    "light": dict(bg="#f6f7f9", card="#ffffff", tx="#1a1d23", mu="#667085", bd="#e2e5ea", ac="#4f6bed",
                  ok="#1a9d5c", wa="#d98a00", er="#e5484d", row="#f1f3f7"),
    "dark": dict(bg="#14161a", card="#1d2026", tx="#eceef2", mu="#9aa1ad", bd="#2d323b", ac="#7f95ff",
                 ok="#3ec98a", wa="#f0b13a", er="#f0675c", row="#252932"),
}


def system_theme():
    try:
        import winreg
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                           r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize")
        return "light" if winreg.QueryValueEx(k, "AppsUseLightTheme")[0] else "dark"
    except Exception:
        return "dark"


def _rr(c, x1, y1, x2, y2, r, **kw):
    """Rounded rectangle on a canvas."""
    r = max(1, min(r, (x2 - x1) // 2, (y2 - y1) // 2))
    pts = [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y2 - r, x2, y2, x2 - r, y2,
           x1 + r, y2, x1, y2, x1, y2 - r, x1, y1 + r, x1, y1]
    return c.create_polygon(pts, smooth=True, **kw)


def report_crash(text):
    """Make a failure visible: log file next to the program, console, and a message box."""
    import os
    try:
        base = os.path.dirname(sys.executable) if getattr(sys, "frozen", False) else os.getcwd()
        with open(os.path.join(base, "aion2_reader_error.log"), "a") as f:
            f.write(time.strftime("%Y-%m-%d %H:%M:%S") + "\n" + text + "\n")
    except Exception:
        pass
    try:
        if sys.__stdout__ is not None:
            sys.__stdout__.write(text + "\n")
    except Exception:
        pass
    try:
        import ctypes
        ctypes.windll.user32.MessageBoxW(0, "The reader hit a problem:\n\n" + text[-900:] +
                                         "\n\n(also saved to aion2_reader_error.log)", "Aion 2 Game Reader", 0x10)
    except Exception:
        pass


def gui_main(start_worker=True, theme=None):
    import tkinter as tk
    import tkinter.font as tkfont
    import queue
    import webbrowser
    q = queue.Queue()
    if start_worker or sys.stdout is None:
        sys.stdout = sys.stderr = _Out(q)
    npcap = npcap_ok()
    admin_ok = is_admin()

    if start_worker and npcap:
        def work():
            try:
                cmd_live(argparse.Namespace(proc="Aion2.exe", wait=True))
            except SystemExit as e:
                LIVE["error"] = str(e)
            except Exception as e:
                LIVE["error"] = "%s. If this mentions permissions or Npcap, run as administrator." % e
        threading.Thread(target=work, daemon=True).start()

    root = tk.Tk()
    root.title("Aion 2 Game Reader")
    root.geometry("660x600")
    root.minsize(560, 460)
    try:                                  # come to the front, even behind the elevated console
        root.lift()
        root.attributes("-topmost", True)
        root.after(600, lambda: root.attributes("-topmost", False))
        root.focus_force()
    except Exception:
        pass

    def tk_error(exc, val, tb):
        import traceback
        txt = "".join(traceback.format_exception(exc, val, tb))
        logbuf.append(txt)
        report_crash(txt) if not LIVE.get("tk_err") else None
        LIVE["tk_err"] = True
    root.report_callback_exception = tk_error
    FONT = "Segoe UI"
    S = {"theme": theme or system_theme(), "log": False, "sig": None}
    logbuf = []
    W = {}

    class RoundBox(tk.Canvas):
        """A card with rounded corners; put children in .inner"""
        def __init__(self, master, parent_bg, fill, outline, radius=14, pad=14):
            super().__init__(master, highlightthickness=0, bd=0, bg=parent_bg, height=2 * pad + 4)
            self.fill, self.outline, self.radius, self.pad = fill, outline, radius, pad
            self.inner = tk.Frame(self, bg=fill)
            self.win = self.create_window(pad, pad, anchor="nw", window=self.inner)
            self.bind("<Configure>", self._draw)
            self.inner.bind("<Configure>", self._fit)
            self.after_idle(self._fit)

        def _fit(self, e=None):
            h = self.inner.winfo_reqheight() + 2 * self.pad
            if int(self.cget("height")) != h:
                self.configure(height=h)

        def _draw(self, e=None):
            self.delete("bg")
            w, h = self.winfo_width(), self.winfo_height()
            _rr(self, 1, 1, w - 1, h - 1, self.radius, fill=self.fill, outline=self.outline, width=1, tags="bg")
            self.tag_lower("bg")
            self.itemconfigure(self.win, width=max(1, w - 2 * self.pad))

    class Pill(tk.Canvas):
        """Outlined button like the ones on the tracker page."""
        def __init__(self, master, text, command, pal, parent_bg, color=None, radius=10):
            f = tkfont.Font(family=FONT, size=10, weight="bold")
            w, h = f.measure(text) + 34, 34
            super().__init__(master, width=w, height=h, bg=parent_bg, highlightthickness=0, bd=0, cursor="hand2")
            self.col = color or pal["ac"]
            self.tx = pal["tx"]
            self.shape = _rr(self, 2, 2, w - 2, h - 2, radius, fill=parent_bg, outline=self.col, width=2)
            self.label = self.create_text(w // 2, h // 2, text=text, fill=self.tx, font=f)
            self.parent_bg = parent_bg
            self.bind("<Enter>", lambda e: (self.itemconfigure(self.shape, fill=self.col),
                                            self.itemconfigure(self.label, fill="#ffffff")))
            self.bind("<Leave>", lambda e: (self.itemconfigure(self.shape, fill=self.parent_bg),
                                            self.itemconfigure(self.label, fill=self.tx)))
            self.bind("<Button-1>", lambda e: command())

    def toggle_log():
        S["log"] = not S["log"]
        build()

    def toggle_theme():
        S["theme"] = "light" if S["theme"] == "dark" else "dark"
        build()

    def build():
        for c in root.winfo_children():
            c.destroy()
        P = PALETTES[S["theme"]]
        W.clear()
        root.configure(bg=P["bg"])
        top = tk.Frame(root, bg=P["bg"])
        top.pack(fill="x", padx=20, pady=(18, 8))
        tl = tk.Frame(top, bg=P["bg"])
        tl.pack(side="left")
        tk.Label(tl, text="Aion 2 Game Reader", bg=P["bg"], fg=P["tx"], font=(FONT, 17, "bold")).pack(anchor="w")
        tk.Label(tl, text="Reads your own game data on this PC and sends it to the tracker page.",
                 bg=P["bg"], fg=P["mu"], font=(FONT, 9)).pack(anchor="w")
        Pill(top, "\u2600 Light" if S["theme"] == "dark" else "\u263E Dark", toggle_theme, P, P["bg"],
             color=P["bd"], radius=10).pack(side="right")

        card = RoundBox(root, P["bg"], P["card"], P["bd"])
        card.pack(fill="x", padx=20, pady=6)
        row = tk.Frame(card.inner, bg=P["card"])
        row.pack(fill="x")
        W["dot"] = tk.Canvas(row, width=16, height=16, bg=P["card"], highlightthickness=0)
        W["dot"].pack(side="left", padx=(0, 10))
        W["oval"] = W["dot"].create_oval(2, 2, 14, 14, fill=P["wa"], outline="")
        W["head"] = tk.Label(row, text="Starting...", bg=P["card"], fg=P["tx"], font=(FONT, 13, "bold"))
        W["head"].pack(side="left")
        W["hint"] = tk.Label(card.inner, text="", bg=P["card"], fg=P["mu"], font=(FONT, 9), justify="left",
                             wraplength=560, anchor="w")
        W["hint"].pack(fill="x", pady=(4, 0))
        card.inner.bind("<Configure>", lambda e: (card._fit(), W["hint"].config(wraplength=max(200, card.winfo_width() - 60))), add="+")

        bar = tk.Frame(root, bg=P["bg"])
        bar.pack(fill="x", padx=20, pady=(8, 4))
        Pill(bar, "Open tracker", lambda: webbrowser.open(TRACKER_URL), P, P["bg"]).pack(side="left")
        Pill(bar, "Hide details" if S["log"] else "Show details", toggle_log, P, P["bg"],
             color=P["bd"]).pack(side="left", padx=10)

        lst = RoundBox(root, P["bg"], P["card"], P["bd"], pad=12)
        lst.pack(fill="both", expand=True, padx=20, pady=(8, 6))
        lst._fit = lambda e=None: None            # this card fills the free space
        W["list"] = tk.Frame(lst.inner, bg=P["card"])
        W["list"].pack(fill="both", expand=True)
        W["P"] = P
        S["sig"] = None

        if S["log"]:
            lg = RoundBox(root, P["bg"], P["card"], P["bd"], pad=10)
            lg.pack(fill="x", padx=20, pady=(0, 6))
            W["logt"] = tk.Text(lg.inner, height=7, bg=P["card"], fg=P["mu"], relief="flat",
                                font=("Consolas", 9), wrap="word", highlightthickness=0)
            W["logt"].pack(fill="x")
            W["logt"].insert("end", "".join(logbuf))
            W["logt"].see("end")
        tk.Label(root, text="Passive reader: it never changes the game. Close this window to stop.",
                 bg=P["bg"], fg=P["mu"], font=(FONT, 8)).pack(anchor="w", padx=20, pady=(0, 10))

    def cls_of(snap, name):
        m = snap.get("classes") or {}
        for k, v in m.items():
            if k.strip().lower() == name.strip().lower():
                return v
        return None

    def class_img(cls):
        """28px class icon (or an empty spacer so the names line up) kept alive for tkinter."""
        cache = S.setdefault("imgs", {})
        if cls not in cache:
            try:
                cache[cls] = tk.PhotoImage(data=CLASS_ICONS[cls]) if cls in CLASS_ICONS else tk.PhotoImage(width=28, height=28)
            except Exception:
                cache[cls] = tk.PhotoImage(width=28, height=28)
        return cache[cls]

    def render_rows(snap):
        P = W["P"]
        cur = snap.get("current")
        chars = sorted(snap.get("characters", {}).items(), key=lambda kv: -kv[1].get("updated", 0))
        data = []
        for name, d in chars:
            asc = "-" if d.get("asc") is None else "%d/3%s" % (d["asc"], " (+%d)" % d["ascExtra"] if d.get("ascExtra") else "")
            nm = "-" if d.get("nm") is None else "%d/14%s" % (d["nm"], " (+%d)" % d["nmExtra"] if d.get("nmExtra") else "")
            data.append((name, name == cur, d.get("energy", "-"), d.get("charged", "-"), asc, nm, cls_of(snap, name)))
        stamps = [d.get("updated") for _, d in chars]
        if data == S["sig"]:
            for lab, ts in zip(S.get("upd", []), stamps):      # only the "x s ago" texts change
                t = ago(ts)
                if lab.cget("text") != t:
                    lab.config(text=t)
            return
        S["sig"] = data
        S["upd"] = []
        lf = W["list"]
        for c in lf.winfo_children():
            c.destroy()
        cols = (("Character", 0, "w", 1), ("Energy", 70, "center", 0), ("Charged", 80, "center", 0),
                ("Ascension", 96, "center", 0), ("Nightmare", 96, "center", 0), ("Updated", 84, "center", 0))
        hd = tk.Frame(lf, bg=P["card"])
        hd.pack(fill="x", padx=8, pady=(0, 4))
        for k, (t, w, an, ex) in enumerate(cols):
            tk.Label(hd, text=t, bg=P["card"], fg=P["mu"], font=(FONT, 9, "bold"), anchor=an).grid(row=0, column=k, sticky="ew")
            hd.grid_columnconfigure(k, weight=ex, minsize=w)
        if not data:
            tk.Label(lf, text="No characters yet. Swap characters in game and they appear here.",
                     bg=P["card"], fg=P["mu"], font=(FONT, 10)).pack(pady=24)
            return
        for (name, is_cur, en, ch, asc, nm, cls), ts in zip(data, stamps):
            rb = RoundBox(lf, P["card"], P["row"], P["ac"] if is_cur else P["row"], radius=10, pad=8)
            rb.pack(fill="x", pady=3)
            fr = rb.inner
            vals = [name, en, ch, asc, nm, ago(ts)]
            for k, (t, w, an, ex) in enumerate(cols):
                lab = tk.Label(fr, text=str(vals[k]), bg=P["row"], fg=P["ac"] if (is_cur and k == 0) else P["tx"],
                               font=(FONT, 10, "bold" if k == 0 else "normal"), anchor=an)
                if k == 0:
                    lab.config(image=class_img(cls), compound="left", padx=2)
                lab.grid(row=0, column=k, sticky="ew")
                fr.grid_columnconfigure(k, weight=ex, minsize=w)
                if k == 5:
                    S["upd"].append(lab)

    def refresh():
        P = W["P"]
        try:
            while True:
                t = q.get_nowait()
                logbuf.append(t)
                if "logt" in W:
                    W["logt"].insert("end", t)
                    W["logt"].see("end")
            del logbuf[:-600]
        except queue.Empty:
            pass
        stt = LIVE.get("state")
        snap = stt.snapshot() if stt else {"characters": {}}
        colour, headline, hint = status_of(LIVE, snap, admin_ok, npcap)
        col = {"green": P["ok"], "amber": P["wa"], "red": P["er"]}[colour]
        W["dot"].itemconfig(W["oval"], fill=col)
        W["head"].config(text=headline)
        W["hint"].config(text=hint)
        render_rows(snap)
        root.after(700, refresh)

    build()
    refresh()

    def close():
        root.destroy()
        import os
        os._exit(0)
    root.protocol("WM_DELETE_WINDOW", close)
    return root


def main():
    if len(sys.argv) == 1:
        print("Opening the reader window...")
        try:
            root = gui_main()
            root.mainloop()
            return
        except ImportError:
            auto_live()
            input("\nPress Enter to close")
            return
        except Exception:
            import traceback
            report_crash(traceback.format_exc())
            return
    if sys.argv[1:] == ["console"]:
        auto_live()
        input("\nPress Enter to close")
        return
    if sys.argv[1:2] == ["diag"]:
        ap = argparse.ArgumentParser(); ap.add_argument("diag"); ap.add_argument("--proc", default="Aion2.exe")
        ap.add_argument("--secs", type=int, default=25)
        try:
            cmd_diag(ap.parse_args())
        except Exception as e:
            print("Error:", e)
        input("\nPress Enter to close")
        return
    if sys.argv[1:2] == ["capture"]:
        ap = argparse.ArgumentParser(); ap.add_argument("capture")
        ap.add_argument("--secs", type=int, default=150); ap.add_argument("--out", default="aion2_capture.jsonl")
        x = ap.parse_args()
        print("Capturing game data for %d seconds into %s. Log in / swap characters now.\n" % (x.secs, x.out))
        try:
            cmd_live(argparse.Namespace(proc="Aion2.exe", wait=True, save=x.out, secs=x.secs))
        except SystemExit as e:
            print(e)
        except Exception as e:
            print("Error:", e)
        print("\nSaved %s next to the program. Send me that file." % x.out)
        input("\nPress Enter to close")
        return
    if sys.argv[1:] == ["menu"]:
        interactive()
        input("\nPress Enter to close")
        return
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    l = sub.add_parser("live"); l.add_argument("--proc", default="Aion2.exe")
    l.add_argument("--port-http", type=int, default=HTTP_PORT, dest="port_http")
    l.add_argument("--origin", action="append", default=[], help="extra web page address allowed to read the values")
    l.set_defaults(fn=cmd_live)
    f = sub.add_parser("file"); f.add_argument("file"); f.add_argument("--port", type=int, default=PORT)
    f.add_argument("--serve", action="store_true", help="after replay, serve the values for testing")
    f.add_argument("--port-http", type=int, default=HTTP_PORT, dest="port_http")
    f.add_argument("--origin", action="append", default=[])
    f.set_defaults(fn=cmd_file)
    a = ap.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
