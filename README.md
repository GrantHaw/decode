# decode.py

You get handed something like `Nzc2OTYzNzk3MzdiNzA2...` in a CTF, and it's hex inside base64 inside who knows what. This throws every common encoding at it and keeps peeling until a flag falls out.

```
$ python3 decode.py -q "Nzc2OTYzNzk3MzdiNzA2NTY1NmM1Zjc0Njg2NTVmNmY2ZTY5NmY2ZTdk"
  base64 -> hex  =>  wicys{peel_the_onion}
```

Just Python 3, nothing to install.

## Usage

```
python3 decode.py "SGVsbG8="           # decode a string
python3 decode.py -f flag.txt          # read from a file
cat flag.txt | python3 decode.py       # or pipe it in
python3 decode.py -p picoCTF "..."     # only look for picoCTF{...}
python3 decode.py -q "..."             # only print flag hits
python3 decode.py -d 6 "..."           # peel deeper (default is 4)
```

If you only remember one flag, make it `-p`. Set it to the event's prefix and most of the noise disappears.

## What it tries

base64, base64url, base32, base58, base85, ascii85, hex (spaces, `0x`, and `\x` are fine), URL encoding, ROT13, ROT47, atbash, all 25 Caesar shifts, binary, octal, decimal, Morse, reversed text, and single-byte XOR on the raw input plus whatever its hex or base64 decodes to.

It does one pass with every decoder, then brute forces Caesar and XOR, then chains decoders up to 4 layers deep and tells you the chain that got there.

## About the noise

Anything shaped like `word{...}` counts as a candidate, which means ROT13 and atbash happily turn a real flag into five fake ones. So results get ranked. A known prefix (`flag`, `ctf`, `picoctf`, `htb`, `wicys`, and a few more) wins outright and hides the junk. Without one, it sorts by how much the text looks like English. That's usually right, but not always, so skim past the first line if it looks off.
