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
            if nm.isprintable() and not nm.isspace():
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

        for j, e, c, dump in scan_resources(b[start:]):
            if outside(start + j):
                ev.append((start + j, "val", (e, c, "plain", dump, None, None)))
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

    # events from the stream decoder
    def on_value(self, e, c, how, dump=False, asc=None, nm=None):
        t = self.clock
        if not dump:                      # a plain update (spent / gained energy)
            self.emit(e, c, how, swap=False)
        elif self.pend_name and t - self.pend_name[1] <= self.WINDOW:
            self.pend_name = None
            self.emit(e, c, how, swap=True, asc=asc, nm=nm)
        else:                             # swap/login dump: wait for the name
            self.pend_vals = (e, c, how, t, asc, nm)

    def on_name(self, nm, sid=None):
        t = self.clock
        if nm == self.name and t - self.name_t < 3.0:
            return                    # same marker repeated within one swap
        self.name = nm
        self.sid = sid
        self.name_t = t
        if self.pend_vals and t - self.pend_vals[3] <= self.WINDOW:
            e, c, how, _, asc, nmv = self.pend_vals
            self.pend_vals = None
            self.emit(e, c, how, swap=True, asc=asc, nm=nmv)
        else:
            self.pend_name = (nm, t)

    def tick(self, now=None):
        """Flush anything that has waited long enough."""
        t = self.clock if now is None else now
        if self.pend_vals and t - self.pend_vals[3] > self.WINDOW:
            e, c, how, _, asc, nmv = self.pend_vals
            self.pend_vals = None
            self.emit(e, c, how, swap=True, asc=asc, nm=nmv)   # a full dump even though no name came
        if self.pend_name and t - self.pend_name[1] > self.WINDOW:
            nm = self.pend_name[0]
            self.pend_name = None
            if nm == self.last_name:
                pass          # same character again (zone change / entering a trial): nothing changed
            elif self.last_name is None:
                print("[%s] %-14s current character (values show up after the next swap/login)"
                      % (time.strftime("%H:%M:%S"), nm))
                self.last_name = nm
            else:
                self.emit(None, None, "no values sent", swap=True)

    def on_asc(self, left, extra):
        """Live Ascension update for the current character (an entry was spent / gained)."""
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
    the allowed web page origins. Read-only: it never accepts data."""
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _cors(self):
            origin = self.headers.get("Origin", "")
            if origin_ok(origin, extra):
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Vary", "Origin")
                self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
                self.send_header("Access-Control-Allow-Headers", "*")
                if self.headers.get("Access-Control-Request-Private-Network"):
                    self.send_header("Access-Control-Allow-Private-Network", "true")
                self.send_header("Access-Control-Max-Age", "600")

        def do_OPTIONS(self):
            self.send_response(204)
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


def cmd_live(a):
    from scapy.all import sniff, TCP, IP
    st = State()
    start_server(st, getattr(a, "port_http", HTTP_PORT), getattr(a, "origin", []) or [])
    streams = {}
    flows = set()
    stop = threading.Event()

    def refresh():
        while not stop.is_set():
            try:
                flows.clear(); flows.update(game_flows(a.proc))
            except Exception:
                pass
            time.sleep(2)
    threading.Thread(target=refresh, daemon=True).start()
    time.sleep(2.5)
    if not flows and getattr(a, "wait", False):
        print("Waiting for %s (start the game and log in; ExitLag OFF)..." % a.proc)
        w = 0
        while not flows:
            time.sleep(1)
            w += 1
            if w % 30 == 0:
                print("  still waiting for %s..." % a.proc)
    if not flows:
        sys.exit("No game connection found for %s. Is the game running and logged in "
                 "(and ExitLag OFF)?" % a.proc)
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
        for lp, rip, rp in flows:
            if ip.src == rip and t.sport == rp and t.dport == lp:
                key = (lp, rip, rp)
                s = streams.get(key)
                if s is None:
                    s = streams[key] = Stream(st.on_value, st.on_name, st.on_asc, st.on_nm)
                st.clock = time.time()
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
        sniff(filter="tcp", prn=on, store=False)
    except KeyboardInterrupt:
        pass
    stop.set()


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


def main():
    if len(sys.argv) == 1:
        auto_live()
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
