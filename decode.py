#!/usr/bin/env python3
# decode - throw every common codec at some input, and try to auto-peel layers
# usage:
#   python3 decode.py "SGVsbG8="           # decode a string
#   python3 decode.py -f flag.txt          # decode a files contents
#   cat flag.txt | python3 decode.py       # or from stdin
#   python3 decode.py -p wicys "..."       # look for wicys{...} specifically
#   python3 decode.py -q "..."             # only print flag hits
#   python3 decode.py -d 6 "..."           # peel deeper (default 4)

import sys, base64, binascii, codecs, urllib.parse, re, argparse

flagpat = None  # set in main, depends on -p

def looks_ok(b):
    # is this mostly printable text, i guess
    if not b:
        return False
    try:
        s = b.decode("utf-8")
    except:
        return False
    good = 0
    for c in s:
        if 32 <= ord(c) < 127 or c in "\n\t\r":
            good = good + 1
    return (good / len(s)) > 0.85

def as_bytes(x):
    if isinstance(x, bytes):
        return x
    return x.encode("utf-8", "ignore")

def as_str(x):
    return as_bytes(x).decode("utf-8", "ignore")

# --- the codecs, each returns bytes or None ---

def d_b64(x):
    s = as_bytes(x).replace(b"\n", b"")
    if not re.fullmatch(rb"[A-Za-z0-9+/=]+", s):
        return None  # stops it "decoding" random garbage
    try:
        return base64.b64decode(s + b"===")
    except:
        return None

def d_b64url(x):
    s = as_bytes(x)
    if not re.fullmatch(rb"[A-Za-z0-9_\-=]+", s) or not re.search(rb"[_\-]", s):
        return None  # only bother if it actually has url-safe chars
    try:
        return base64.urlsafe_b64decode(s + b"===")
    except:
        return None

def d_b32(x):
    s = as_bytes(x).upper()
    try:
        pad = (-len(s)) % 8
        return base64.b32decode(s + b"=" * pad)
    except:
        return None

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def d_b58(x):
    s = as_str(x).strip()
    if not s or any(c not in B58 for c in s):
        return None
    n = 0
    for c in s:
        n = n * 58 + B58.index(c)
    out = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    lead = len(s) - len(s.lstrip("1"))  # leading 1s are zero bytes
    return b"\x00" * lead + out

def d_b85(x):
    try:
        return base64.b85decode(as_bytes(x))
    except:
        return None

def d_a85(x):
    s = as_bytes(x)
    try:
        if s.startswith(b"<~"):
            return base64.a85decode(s, adobe=True)
        return base64.a85decode(s)
    except:
        return None

def d_hex(x):
    s = as_bytes(x).replace(b" ", b"").replace(b"\n", b"").replace(b"0x", b"").replace(b"\\x", b"")
    try:
        return binascii.unhexlify(s)
    except:
        return None

def d_url(x):
    if b"%" not in as_bytes(x):
        return None
    try:
        return urllib.parse.unquote_to_bytes(as_bytes(x))
    except:
        return None

def d_rot13(x):
    try:
        return codecs.encode(as_str(x), "rot13").encode()
    except:
        return None

def d_rot47(x):
    out = ""
    for c in as_str(x):
        o = ord(c)
        if 33 <= o <= 126:
            out = out + chr(33 + ((o - 33 + 47) % 94))
        else:
            out = out + c
    return out.encode()

def d_atbash(x):
    out = ""
    for c in as_str(x):
        if "a" <= c <= "z":
            out = out + chr(ord("z") - (ord(c) - ord("a")))
        elif "A" <= c <= "Z":
            out = out + chr(ord("Z") - (ord(c) - ord("A")))
        else:
            out = out + c
    return out.encode()

def d_rev(x):
    return as_bytes(x)[::-1]

def d_bin(x):
    # "01001000 01101001" style, or one long blob of bits
    s = as_str(x).split()
    if len(s) == 1 and len(s[0]) % 8 == 0:
        s = [s[0][i:i + 8] for i in range(0, len(s[0]), 8)]
    try:
        if s and all(set(p) <= set("01") for p in s):
            return bytes(int(p, 2) for p in s)
    except:
        pass
    return None

def d_oct(x):
    # "110 151" style
    s = as_str(x).replace("\\", " ").split()
    try:
        if s and all(set(p) <= set("01234567") for p in s) and any(len(p) == 3 for p in s):
            return bytes(int(p, 8) for p in s)
    except:
        pass
    return None

def d_dec(x):
    # "72 105" style, commas too
    s = as_str(x).replace(",", " ").split()
    try:
        if s and all(p.isdigit() for p in s):
            return bytes(int(p) for p in s)
    except:
        pass
    return None

MORSE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F", "--.": "G", "....": "H",
    "..": "I", ".---": "J", "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O", ".--.": "P",
    "--.-": "Q", ".-.": "R", "...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X",
    "-.--": "Y", "--..": "Z", "-----": "0", ".----": "1", "..---": "2", "...--": "3", "....-": "4",
    ".....": "5", "-....": "6", "--...": "7", "---..": "8", "----.": "9", "..--.-": "_",
    "-.--.": "(", "-.--.-": ")", ".-.-.-": ".", "--..--": ",", "..--..": "?", "-.-.--": "!",
}

def d_morse(x):
    s = as_str(x).strip()
    if not s or set(s) - set(".-/ |\n"):
        return None
    words = re.split(r"\s*[/|]\s*|\s{3,}", s)
    out = []
    for w in words:
        letters = []
        for l in w.split():
            if l not in MORSE:
                return None
            letters.append(MORSE[l])
        out.append("".join(letters))
    return " ".join(out).encode()

codecs_list = [
    ("base64", d_b64),
    ("base64url", d_b64url),
    ("base32", d_b32),
    ("base58", d_b58),
    ("base85", d_b85),
    ("ascii85", d_a85),
    ("hex", d_hex),
    ("url", d_url),
    ("rot13", d_rot13),
    ("rot47", d_rot47),
    ("atbash", d_atbash),
    ("reverse", d_rev),
    ("binary", d_bin),
    ("octal", d_oct),
    ("decimal", d_dec),
    ("morse", d_morse),
]

# prefixes that are almost certainly a real flag
KNOWN = ["flag", "ctf", "wicys", "picoctf", "htb", "thm", "ritsec", "csaw", "uiuctf", "duckerz", "key"]

# rough english letter freqs, used to rank which decode reads most like words
FREQ = {"e": 12.7, "t": 9.1, "a": 8.2, "o": 7.5, "i": 7.0, "n": 6.7, "s": 6.3, "h": 6.1, "r": 6.0, "d": 4.3,
        "l": 4.0, "c": 2.8, "u": 2.8, "m": 2.4, "w": 2.4, "f": 2.2, "g": 2.0, "y": 2.0, "p": 1.9, "b": 1.5,
        "v": 1.0, "k": 0.8, "j": 0.15, "x": 0.15, "q": 0.1, "z": 0.07}

def hit(txt):
    return flagpat.search(txt) is not None

def score(txt):
    # higher = more likely the real thing. known prefix is a huge bonus, then englishness
    m = flagpat.search(txt)
    if not m:
        return 0
    f = m.group(0).lower()
    sc = 0
    if any(f.startswith(k + "{") for k in KNOWN):
        sc = sc + 100
    letters = [c for c in f if c.isalpha()]
    if letters:
        sc = sc + sum(FREQ.get(c, 0) for c in letters) / len(letters)
    return sc

def top(rows, n):
    # rows are (score, line). keep the best n, but always keep known-prefix ones
    rows.sort(key=lambda r: -r[0])
    out = [r for r in rows if r[0] >= 100]
    if out:
        return out  # got a real looking one, skip the junk guesses
    for r in rows:
        if len(out) >= n:
            break
        if r not in out:
            out.append(r)
    return out

def short(txt):
    if len(txt) > 200:
        return txt[:200] + "..."
    return txt

def one_pass(data, quiet):
    if not quiet:
        print("== single pass ==")
    for name, fn in codecs_list:
        out = fn(data)
        if out is not None and looks_ok(out) and out != as_bytes(data):
            txt = out.decode("utf-8", "ignore").strip()
            h = hit(txt)
            if quiet and not h:
                continue
            print("  " + name + ": " + short(txt) + ("   >>> FLAG?" if h else ""))

def caesar(data, quiet):
    # all 25 shifts, only show ones that hit the flag pattern (otherwise its 25 lines of noise)
    s = as_str(data)
    rows = []
    for k in range(1, 26):
        out = ""
        for c in s:
            if "a" <= c <= "z":
                out = out + chr((ord(c) - 97 + k) % 26 + 97)
            elif "A" <= c <= "Z":
                out = out + chr((ord(c) - 65 + k) % 26 + 65)
            else:
                out = out + c
        if hit(out):
            rows.append((score(out), "  shift " + str(k) + ": " + short(out) + "   >>> FLAG?"))
    rows = top(rows, 2)
    if rows and not quiet:
        print("== caesar (best guesses) ==")
    for r in rows:
        print(r[1])

def xor1(raw, quiet):
    # single byte xor brute force. tries the raw bytes and the hex-decoded bytes
    cands = [("raw", raw)]
    hx = d_hex(raw)
    if hx:
        cands.append(("hex", hx))
    b6 = d_b64(raw)
    if b6 and not looks_ok(b6):
        cands.append(("base64", b6))  # binary-ish base64 is a classic xor setup
    rows = []
    for label, b in cands:
        for k in range(1, 256):
            out = bytes(c ^ k for c in b)
            if looks_ok(out):
                t = out.decode("utf-8", "ignore")
                if hit(t):
                    rows.append((score(t), "  " + label + " ^ 0x" + format(k, "02x") + ": " + short(t) + "   >>> FLAG?"))
    rows = top(rows, 2)
    if rows and not quiet:
        print("== single byte xor (best guesses) ==")
    for r in rows:
        print(r[1])

def deep(data, depth, chain, seen, hits):
    # recursively peel, up to depth, collect flag-looking results
    if depth <= 0:
        return
    for name, fn in codecs_list:
        if name in ("reverse", "atbash", "rot13", "rot47") and chain and chain[-1] == name:
            continue  # these undo themselves, dont ping pong
        out = fn(data)
        if out is None or not looks_ok(out):
            continue
        if out == as_bytes(data):
            continue
        key = out[:60]
        if key in seen:
            continue
        seen.add(key)
        txt = out.decode("utf-8", "ignore").strip()
        newchain = chain + [name]
        if hit(txt):
            hits.append((" -> ".join(newchain), txt))
        deep(out, depth - 1, newchain, seen, hits)

def main():
    global flagpat
    ap = argparse.ArgumentParser(description="throw every common codec at something and peel the layers")
    ap.add_argument("data", nargs="?", help="the string to decode (or use -f / stdin)")
    ap.add_argument("-f", "--file", help="read input from a file")
    ap.add_argument("-p", "--prefix", help="flag prefix to look for, eg wicys or picoCTF")
    ap.add_argument("-d", "--depth", type=int, default=4, help="how many layers to peel (default 4)")
    ap.add_argument("-q", "--quiet", action="store_true", help="only print flag hits")
    a = ap.parse_args()

    if a.prefix:
        flagpat = re.compile(re.escape(a.prefix) + r"\{[^}]+\}", re.I)
    else:
        # generic flag-ish pattern, catches wicys{...}, flag{...}, etc
        flagpat = re.compile(r"[a-z0-9_]{2,}\{[^}]{1,}\}", re.I)

    if a.file:
        data = open(a.file, "rb").read()
    elif a.data:
        data = a.data.encode()
    elif not sys.stdin.isatty():
        data = sys.stdin.buffer.read()
    else:
        ap.print_help()
        return

    data = data.strip()
    if hit(as_str(data)):
        print(">>> the input already has a flag in it: " + flagpat.search(as_str(data)).group(0))

    one_pass(data, a.quiet)
    caesar(data, a.quiet)
    xor1(data, a.quiet)

    if not a.quiet:
        print()
        print("== deep peel (" + str(a.depth) + " layers) ==")
    hits = []
    deep(data, a.depth, [], set(), hits)
    # same flag reached different ways? keep the shortest chain
    best = {}
    for chain, txt in hits:
        f = flagpat.search(txt).group(0)
        if f not in best or chain.count("->") < best[f][0].count("->"):
            best[f] = (chain, txt)
    rows = top([(score(t), "  " + c + "  =>  " + short(t)) for c, t in best.values()], 3)
    if rows:
        for r in rows:
            print(r[1])
    elif not a.quiet:
        print("  no multi-layer flag found (try the single pass results above)")

if __name__ == "__main__":
    main()
