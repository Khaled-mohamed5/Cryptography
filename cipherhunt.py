#!/usr/bin/env python3
"""
CipherHunt - a terminal hunt through eight ciphers.

You are in a tomb. Each chamber is sealed by a cipher. Crack it, speak the
word, walk deeper. No libraries, no internet, just you and the bytes.

    python3 cipherhunt.py              # start (or resume) the hunt
    python3 cipherhunt.py --board      # see how far you got
    python3 cipherhunt.py --reset      # wipe progress, start clean
    python3 cipherhunt.py --lair       # build a real lair on disk to hunt
                                       # with grep / strings / xxd / base64
    python3 cipherhunt.py --verify     # check the flags you dug out of the lair
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import random
import string
import sys
import textwrap
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
SAVE_PATH = HERE / ".cipherhunt_save.json"
LAIR_SEED = "cairo-sand-and-feistel-rounds"
ALPHA = string.ascii_uppercase


# --------------------------------------------------------------- presentation

COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def paint(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if COLOR else text


def gold(t):  return paint("38;5;179", t)
def sand(t):  return paint("38;5;180", t)
def green(t): return paint("38;5;114", t)
def red(t):   return paint("38;5;167", t)
def cyan(t):  return paint("38;5;080", t)
def dim(t):   return paint("2", t)
def bold(t):  return paint("1", t)


BANNER = r"""
   ___ _       _              _   _             _
  / __(_)_ __ | |__   ___ _ _| | | |_   _ _ __ | |_
 | |  | | '_ \| '_ \ / _ \ '__| |_| | | | | '_ \| __|
 | |__| | |_) | | | |  __/ |  |  _  | |_| | | | | |_
  \___|_| .__/|_| |_|\___|_|  |_| |_|\__,_|_| |_|\__|
        |_|      eight chambers. eight ciphers. one word each.
"""


def rule(width: int = 68) -> str:
    return dim("-" * width)


def wrap(text: str, indent: str = "  ", subsequent: str | None = None) -> str:
    tail = indent if subsequent is None else subsequent
    return "\n".join(
        textwrap.fill(line, 68, initial_indent=indent, subsequent_indent=tail)
        if line.strip() else line
        for line in text.strip().splitlines()
    )


def show_cipher(text: str) -> None:
    """One logical line, always. The terminal soft wraps it; a copy paste
    into the toolbelt then still arrives in one piece."""
    print(cyan("  " + text))


# -------------------------------------------------------------------- ciphers

def caesar(text: str, shift: int) -> str:
    out = []
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            out.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            out.append(ch)
    return "".join(out)


def vigenere(text: str, key: str, decrypt: bool = False) -> str:
    out, ki, key = [], 0, key.upper()
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            k = ord(key[ki % len(key)]) - ord("A")
            out.append(chr((ord(ch) - base + (-k if decrypt else k)) % 26 + base))
            ki += 1
        else:
            out.append(ch)
    return "".join(out)


def xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def sub_map(seed: int = 1337) -> dict:
    rng = random.Random(seed)
    plain, cipher = list(ALPHA), list(ALPHA)
    while True:
        rng.shuffle(cipher)
        if all(a != b for a, b in zip(plain, cipher)):
            return dict(zip(plain, cipher))


def substitute(text: str, mapping: dict) -> str:
    return "".join(mapping.get(ch, ch) for ch in text.upper())


def to_bits(text: str) -> str:
    return " ".join(format(b, "08b") for b in text.encode())


def normalise(answer: str) -> str:
    return "".join(ch for ch in answer.upper() if ch.isalnum())


# -------------------------------------------------------------------- chambers

def build_chambers() -> list:
    """Every ciphertext is generated here, so the puzzles can never drift."""

    # 1 - Caesar
    p1 = "THE VAULT DOOR ANSWERS ONLY TO THE WORD OBELISK"
    c1 = caesar(p1, 7)

    # 2 - Base64, twice
    p2 = "the second seal opens on the word SCARAB. keep descending."
    c2 = base64.b64encode(base64.b64encode(p2.encode())).decode()

    # 3 - reversed, then hex
    p3 = "keep going. the sign carved above the arch is PAPYRUS"
    c3 = p3[::-1].encode().hex()

    # 4 - single byte XOR
    p4 = ("frequency analysis cracks me wide open. the word is ANUBIS "
          "and the key for the next chamber is NILE")
    c4 = xor_bytes(p4.encode(), bytes([0x5B])).hex()

    # 5 - Vigenere, key recovered from chamber 4
    p5 = "THE HIDDEN CHAMBER BEYOND THIS WALL IS NAMED HORIZON"
    c5 = vigenere(p5, "NILE")

    # 6 - monoalphabetic substitution
    p6 = ("THE SPHINX KEEPS ONE EYE OPEN WHILE THE DESERT SLEEPS AND EVERY "
          "TRAVELLER WHO REACHES THIS STONE MUST SPEAK THE NAME OF THE BEAST "
          "THAT GUARDS THE STAIR AND THE NAME OF THE BEAST IS SPHINX")
    smap = sub_map()
    c6 = substitute(p6, smap)
    top_cipher = max(set(c6.replace(" ", "")), key=c6.count)

    # 7 - raw bits, the way Main.java does it
    p7 = "DES chews bits for breakfast. the word is FEISTEL"
    c7 = to_bits(p7)

    # 8 - key reuse: one pad, two messages
    p8a = "the pharaoh sleeps beneath the cold sand tonight"
    p8b = "the last word of this hunt is CARTOUCHE. well done"
    width = max(len(p8a), len(p8b))
    p8a, p8b = p8a.ljust(width), p8b.ljust(width)
    c8 = xor_bytes(p8a.encode(), p8b.encode()).hex()

    return [
        dict(
            n=1, title="The Scratched Lintel", answer="OBELISK", cipher=c1,
            flavor="Somebody chiselled this over the entrance and thought "
                   "sliding the alphabet along was clever. It was, in 50 BC.",
            hints=["Every letter moved the same distance. There are only 25 "
                   "guesses to make, and a computer makes them instantly.",
                   "Try `caesar` here, or in a real shell: "
                   "`echo '...' | tr 'A-Z' 'H-ZA-G'`. The shift is 7."],
            shell="tr 'A-Za-z' 'N-ZA-Mn-za-m'   # rot13, the classic",
        ),
        dict(
            n=2, title="The Padded Door", answer="SCARAB", cipher=c2,
            flavor="Letters, digits, and a couple of '=' signs holding up the "
                   "rear. That trailing padding is a fingerprint.",
            hints=["This is base64. Decode it and look closely at what falls "
                   "out - the job is not finished after one pass.",
                   "It was encoded twice. Decode, then decode again: "
                   "`base64 -d | base64 -d`."],
            shell="echo '<blob>' | base64 -d",
        ),
        dict(
            n=3, title="The Mirrored Slab", answer="PAPYRUS", cipher=c3,
            flavor="Pairs of hex digits, all of them in printable ASCII range. "
                   "The bytes are honest. Their order is not.",
            hints=["Turn the hex into bytes first. `xxd -r -p` does it in one "
                   "breath.",
                   "The text reads backwards. Decode the hex, then reverse it "
                   "with `rev`."],
            shell="echo '<hex>' | xxd -r -p | rev",
        ),
        dict(
            n=4, title="The Single Key", answer="ANUBIS", cipher=c4,
            flavor="Hex again, but nothing readable comes out. One byte was "
                   "XORed over the whole message, over and over.",
            hints=["A one byte key has 256 possibilities. Try all of them and "
                   "keep whichever result is mostly printable English.",
                   "The key is 0x5B. Use `xor` on the hex above - and read the "
                   "whole plaintext, the next chamber needs a word from it."],
            shell="# brute force 256 keys - `xor <hex>` does it for you here",
        ),
        dict(
            n=5, title="The Repeating Key", answer="HORIZON", cipher=c5,
            flavor="Letters only, spaces intact, and no letter maps to one "
                   "fixed partner. A key is cycling underneath.",
            hints=["Chamber 4's plaintext handed you the key in plain sight. "
                   "Go re-read it.",
                   "It is a Vigenere cipher with the key NILE. "
                   "Run: `vig <ciphertext> NILE`."],
            shell="# Vigenere: subtract the key letters, cycling as you go",
        ),
        dict(
            n=6, title="The Sphinx's Alphabet", answer="SPHINX", cipher=c6,
            flavor="Each letter always becomes the same other letter. No key "
                   "to guess - only the shape of English to lean on.",
            hints=[f"Count the letters. '{top_cipher}' appears more than any "
                   "other, and in English that is almost always E. "
                   "One letter words and THE patterns do the rest.",
                   "`freq` will rank the letters for you. The three letter "
                   f"word that opens the message is THE, so '{c6[0]}' is T."],
            shell="fold -w1 | sort | uniq -c | sort -rn   # frequency, in shell",
        ),
        dict(
            n=7, title="The Feistel Gate", answer="FEISTEL", cipher=c7,
            flavor="Bits. Groups of eight. Your own DES.java speaks this "
                   "dialect - Main.stringToBinary writes it, "
                   "Main.binaryToString reads it.",
            hints=["Every eight bits is one byte, and every byte is one ASCII "
                   "character.",
                   "Use `bits <the binary>` - or feed it to binaryToString in "
                   "the Java sitting next to this file."],
            shell="# 01000100 -> 0x44 -> 'D'",
        ),
        dict(
            n=8, title="The Reused Pad", answer="CARTOUCHE", cipher=c8,
            flavor="Two messages. One pad. The scribe used the same key twice "
                   "and that is the whole mistake.\n\n"
                   "  You are looking at (message A XOR message B) in hex.\n"
                   "  Message A was intercepted in the clear, and it reads:\n\n"
                   f"      \"{p8a.strip()}\"",
            hints=["XOR cancels the key: A^B XOR A gives you B. The pad never "
                   "even enters the equation.",
                   "Run `xorkey <hex> <message A>` and read what message B "
                   "says. Type message A exactly, spaces and all."],
            shell="# c = A^B, so B = c ^ A. The key is irrelevant. That is the bug.",
        ),
    ]


# ------------------------------------------------------------------- toolbelt

def tool_caesar(arg: str) -> None:
    if not arg:
        return print(dim("  usage: caesar <text>"))
    print(dim("  every shift, so you can eyeball the English one:"))
    for s in range(1, 26):
        print(f"  {s:>2}  {caesar(arg, -s)[:60]}")


def tool_b64(arg: str) -> None:
    try:
        out = base64.b64decode(arg + "===")
    except (binascii.Error, ValueError) as exc:
        return print(red(f"  not valid base64: {exc}"))
    if not out:
        return print(red("  nothing decoded - that is not base64"))
    print("  " + out.decode("utf-8", "replace"))


def tool_hex(arg: str) -> None:
    try:
        print("  " + bytes.fromhex(arg.replace(" ", "")).decode("utf-8", "replace"))
    except ValueError as exc:
        print(red(f"  not valid hex: {exc}"))


def tool_bits(arg: str) -> None:
    raw = "".join(ch for ch in arg if ch in "01")
    if len(raw) % 8:
        return print(red(f"  {len(raw)} bits is not a whole number of bytes"))
    data = bytes(int(raw[i:i + 8], 2) for i in range(0, len(raw), 8))
    print("  " + data.decode("utf-8", "replace"))


def english_score(data: bytes) -> float:
    """Rough 'does this look like English' score. Spaces carry most of it."""
    score = 0.0
    for b in data:
        c = chr(b).lower()
        if c == " ":
            score += 1.8
        elif c in "etaoinshrdlu":
            score += 1.0
        elif c.isalpha() or c in ".,\'":
            score += 0.3
        elif not 32 <= b < 127:
            score -= 4.0
    return score / max(len(data), 1)


def tool_xor(arg: str) -> None:
    """Brute force all 256 one byte keys, rank them by how English they look."""
    try:
        data = bytes.fromhex(arg.replace(" ", ""))
    except ValueError as exc:
        return print(red(f"  not valid hex: {exc}"))
    if not data:
        return print(dim("  usage: xor <hex>"))

    ranked = sorted(((english_score(xor_bytes(data, bytes([k]))), k)
                     for k in range(256)), reverse=True)
    print(dim("  best five keys, scored on how much they look like English:"))
    for rank, (score, key) in enumerate(ranked[:5]):
        out = xor_bytes(data, bytes([key])).decode("utf-8", "replace")
        line = f"  key 0x{key:02x}  {score:5.2f}  {out[:56]}"
        print(green(line) if rank == 0 else dim(line))
    if ranked[0][0] < 0.5:
        print(dim("  none of them scored well - the key is probably longer than one byte"))


def tool_xorkey(arg: str) -> None:
    head, _, key = arg.partition(" ")
    if not key:
        return print(dim("  usage: xorkey <hex> <key text>"))
    try:
        data = bytes.fromhex(head.replace(" ", ""))
    except ValueError as exc:
        return print(red(f"  not valid hex: {exc}"))
    print("  " + xor_bytes(data, key.encode()).decode("utf-8", "replace"))


def tool_vig(arg: str) -> None:
    text, _, key = arg.rpartition(" ")
    if not text or not key.isalpha():
        return print(dim("  usage: vig <ciphertext> <KEY>"))
    print("  " + vigenere(text, key, decrypt=True))


def tool_freq(arg: str) -> None:
    letters = [ch for ch in arg.upper() if ch.isalpha()]
    if not letters:
        return print(dim("  usage: freq <text>"))
    counts = sorted({c: letters.count(c) for c in set(letters)}.items(),
                    key=lambda kv: (-kv[1], kv[0]))
    print("  " + "   ".join(f"{c}:{n}" for c, n in counts[:12]))
    print(dim("  English, most common first:  E T A O I N S H R D L U"))


TOOLS = {
    "caesar": (tool_caesar, "caesar <text>      all 25 shifts at once"),
    "rot13":  (lambda a: print("  " + caesar(a, 13)), "rot13 <text>       shift by 13"),
    "b64":    (tool_b64,    "b64 <text>         base64 decode"),
    "hex":    (tool_hex,    "hex <hexdigits>    hex to bytes"),
    "bits":   (tool_bits,   "bits <01010101>    8 bit groups to ASCII"),
    "xor":    (tool_xor,    "xor <hex>          brute force all 256 one byte keys"),
    "xorkey": (tool_xorkey, "xorkey <hex> <key> XOR against a key you supply"),
    "vig":    (tool_vig,    "vig <text> <KEY>   Vigenere decrypt"),
    "freq":   (tool_freq,   "freq <text>        letter frequency count"),
    "rev":    (lambda a: print("  " + a[::-1]), "rev <text>         reverse it"),
}


def show_tools() -> None:
    print(bold("\n  your toolbelt") + dim("  (type these at any prompt)"))
    for _, help_text in TOOLS.values():
        print("    " + help_text)
    print(bold("\n  and the real thing") + dim("  (these are the shell commands worth knowing)"))
    for line in [
        "echo 'aGk=' | base64 -d              decode base64",
        "echo '6869' | xxd -r -p              hex to bytes",
        "xxd -p file                          bytes to hex",
        "tr 'A-Za-z' 'N-ZA-Mn-za-m'           rot13",
        "rev                                  reverse each line",
        "fold -w1 | sort | uniq -c | sort -rn frequency count",
        "strings -n 6 file                    printable runs inside a binary",
        "grep -rn 'HUNT{' .                   hunt a pattern through a tree",
    ]:
        print("    " + line)
    print(dim("\n    hint  skip  status  board  quit"))


# ----------------------------------------------------------------- persistence

def load_save() -> dict:
    try:
        return json.loads(SAVE_PATH.read_text())
    except (OSError, ValueError):
        return {"cleared": [], "skipped": [], "score": 0, "hints": {}, "elapsed": 0.0}


def write_save(state: dict) -> None:
    try:
        SAVE_PATH.write_text(json.dumps(state, indent=2))
    except OSError:
        pass


def show_board(state: dict, chambers: list) -> None:
    cleared, skipped = set(state["cleared"]), set(state.get("skipped", []))
    print(bold("\n  the tomb\n"))
    for ch in chambers:
        if ch["n"] in skipped:
            mark, name = sand("[~]"), sand(ch["title"])
            word = dim(f"  <- {ch['answer']}  (skipped)")
        elif ch["n"] in cleared:
            mark, name = green("[x]"), green(ch["title"])
            word = dim(f"  <- {ch['answer']}")
        elif ch["n"] == min((c["n"] for c in chambers if c["n"] not in cleared),
                            default=0):
            mark, name, word = gold("[>]"), bold(ch["title"]), dim("  <- you are here")
        else:
            mark, name, word = dim("[ ]"), dim(ch["title"]), ""
        print(f"   {mark} {ch['n']}. {name}{word}")
    mins = int(state.get("elapsed", 0)) // 60
    solved = len(cleared - skipped)
    print(f"\n  score {bold(str(state['score']))}   "
          f"cracked {solved}/{len(chambers)}"
          + (f"   skipped {len(skipped)}" if skipped else "")
          + f"   time {mins}m\n")


# ------------------------------------------------------------------- the hunt

def play_chamber(ch: dict, state: dict) -> str:
    """Returns 'cleared', 'skipped' or 'quit'."""
    used = state["hints"].get(str(ch["n"]), 0)

    print(rule())
    print(f"\n  {gold('CHAMBER ' + str(ch['n']))}  {bold(ch['title'])}\n")
    print(wrap(ch["flavor"]))
    print()
    show_cipher(ch["cipher"])
    print()
    print(dim("  speak the word to open the door, or type: hint / tools / skip / quit"))

    while True:
        try:
            raw = input(gold("\n  > ")).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return "quit"
        if not raw:
            continue

        head, _, arg = raw.partition(" ")
        low = head.lower()

        if low in ("quit", "exit"):
            return "quit"
        if low == "tools":
            show_tools()
            continue
        if low == "board":
            show_board(state, build_chambers())
            continue
        if low == "status":
            print(f"  chamber {ch['n']}, hints used {used}, score {state['score']}")
            continue
        if low == "skip":
            print(red(f"  the door opens on its own. the word was "
                      f"{bold(ch['answer'])}. no points."))
            return "skipped"
        if low == "hint":
            if used >= len(ch["hints"]):
                print(dim("  no hints left. try `tools`, or `skip` to move on."))
                continue
            print(sand("\n" + wrap(ch["hints"][used], "  * ", "    ")))
            used += 1
            state["hints"][str(ch["n"])] = used
            write_save(state)
            continue
        if low in TOOLS:
            TOOLS[low][0](arg.strip())
            continue

        if normalise(raw) == normalise(ch["answer"]):
            points = max(25, 100 - 25 * used)
            state["score"] += points
            print(green(f"\n  the stone slides back.  +{points} points"))
            return "cleared"

        print(red("  the door does not move.") +
              dim("  (`hint` costs 25, `tools` costs nothing)"))


def run_hunt(start_at: int | None = None) -> int:
    chambers = build_chambers()
    state = load_save()
    if start_at:
        state["cleared"] = [c["n"] for c in chambers if c["n"] < start_at]

    if not sys.stdin.isatty():
        print("CipherHunt needs a terminal to play in.")
        show_board(state, chambers)
        return 1

    print(gold(BANNER))
    if state["cleared"]:
        print(dim(f"  resuming - {len(state['cleared'])} chambers already behind you\n"))
    else:
        print(wrap("Eight sealed chambers, each one a different cipher. Crack "
                   "the ciphertext, speak the word it hides, and the door "
                   "opens. Type `tools` for your kit - it prints the real "
                   "shell commands too, which is the whole point."))
        print()

    began = time.time()
    for ch in chambers:
        if ch["n"] in state["cleared"]:
            continue
        result = play_chamber(ch, state)
        state["elapsed"] = state.get("elapsed", 0) + (time.time() - began)
        began = time.time()
        if result == "skipped":
            state.setdefault("skipped", []).append(ch["n"])
        if result == "quit":
            write_save(state)
            print(dim("\n  progress saved. `python3 cipherhunt.py` picks it back up.\n"))
            return 0
        state["cleared"].append(ch["n"])
        write_save(state)

    show_board(state, chambers)
    print(green(bold("  every chamber is open.")))
    print(wrap("You just did classical substitution, base64, hex, single byte "
               "XOR brute force, Vigenere, frequency analysis, raw bit "
               "decoding, and a key reuse break. That last one is not a toy - "
               "reusing a keystream is exactly how real systems have leaked "
               "plaintext.\n\nNow go hunt with the real shell tools:"))
    print(gold("\n    python3 cipherhunt.py --lair\n"))
    return 0


# ------------------------------------------------------------------- the lair

def lair_flag(index: int) -> str:
    """Deterministic, and not sitting in this source file in plaintext."""
    digest = hashlib.sha256(f"{LAIR_SEED}:{index}".encode()).hexdigest()
    adjectives = ["buried", "cracked", "silent", "amber", "hollow", "salted"]
    nouns = ["ibis", "scarab", "cobra", "jackal", "falcon", "lotus"]
    a = adjectives[int(digest[:2], 16) % len(adjectives)]
    n = nouns[int(digest[2:4], 16) % len(nouns)]
    return f"HUNT{{{a}_{n}_{digest[4:10]}}}"


def build_lair(root: Path) -> None:
    rng = random.Random(LAIR_SEED)
    filler = ("sand drifts over the ridge", "the camels are restless",
              "compass reads north, probably", "ink running low",
              "another empty chamber", "the wind again, all night",
              "supplies down to four days", "found a broken jar, nothing in it")

    (root / "camp").mkdir(parents=True, exist_ok=True)
    (root / "dunes").mkdir(parents=True, exist_ok=True)
    (root / "tomb" / "shards").mkdir(parents=True, exist_ok=True)

    (root / "camp" / "START.txt").write_text(textwrap.dedent("""\
        FIELD NOTES - read this first
        =============================

        Five flags are hidden in this dig site. They all look like:

            HUNT{word_word_abc123}

        Nothing here needs a script. Five shell tools find all five:

            grep      search text through a whole tree
            find      search by name, including hidden files
            strings   pull printable runs out of a binary
            base64    decode a base64 blob
            cat       glue files back together in order

        Some starting moves, in rough order of usefulness:

            grep -rn 'HUNT{' .            the blunt instrument. try it first,
                                          then work out why it only finds one.
            ls -la dunes/                 -a is the whole trick sometimes
            find . -type f | sort         see everything, decoys included
            file dunes/sandstorm.bin      ask what a file even is
            strings -n 8 dunes/sandstorm.bin
            base64 -d tomb/inscription.b64
            cat tomb/shards/*.frag        does shell glob order match sort order?
            tr 'A-Za-z' 'N-ZA-Mn-za-m'    rot13, for when text looks almost right

        When you have all five:

            python3 cipherhunt.py --verify
        """))

    # 1 - one flag line buried in a long log. grep.
    lines = []
    for i in range(600):
        lines.append(f"day {i // 12 + 1:>3} :: {rng.choice(filler)}")
        if i == 411:
            lines.append(f"day  35 :: prised a tile loose, something painted under it: {lair_flag(1)}")
    (root / "camp" / "journal.log").write_text("\n".join(lines) + "\n")

    # 2 - hidden file, and rot13 inside it so a blunt grep walks right past.
    (root / "dunes" / ".buried-cache").write_text(
        "you found the dotfile. most people never type ls -a.\n"
        "the last line is rot13, because grep should not get this one for free:\n"
        f"{caesar(lair_flag(2), 13)}\n")

    # 3 - flag embedded in binary noise. strings.
    noise = bytes(rng.randrange(256) for _ in range(2048))
    payload = f"\x00\x00{lair_flag(3)}\x00\x00".encode()
    cut = 1100
    (root / "dunes" / "sandstorm.bin").write_bytes(noise[:cut] + payload + noise[cut:])

    # 4 - base64 blob. base64 -d.
    inscription = (f"carved on the inner wall, in a script nobody bothered to "
                   f"encrypt properly: {lair_flag(4)}\n")
    (root / "tomb" / "inscription.b64").write_text(
        base64.b64encode(inscription.encode()).decode() + "\n")

    # 5 - flag split across ordered fragments. cat with a sane glob.
    flag5 = lair_flag(5)
    chunk = -(-len(flag5) // 12)
    for i in range(12):
        piece = flag5[i * chunk:(i + 1) * chunk]
        (root / "tomb" / "shards" / f"part-{i + 1:02d}.frag").write_text(piece)

    # decoys, because a real hunt has dead ends
    (root / "tomb" / "notes.txt").write_text(
        "HUNT{almost_but_no_this_is_a_decoy}\n"
        "the real ones are longer and end in six hex digits.\n")
    (root / "dunes" / "readme.txt").write_text("nothing here. keep digging.\n")

    print(green(f"\n  lair built at {bold(str(root))}"))
    print(wrap("Five flags are in there. Start with:\n\n"
               f"    cat {root}/camp/START.txt\n\n"
               "Then hunt with grep, find, strings, base64 and cat. When you "
               "have all five, run `python3 cipherhunt.py --verify`."))
    print()


def verify_flags(supplied: list) -> int:
    expected = [lair_flag(i) for i in range(1, 6)]
    if not supplied:
        if not sys.stdin.isatty():
            print("pass the flags as arguments, or run this in a terminal.")
            return 1
        print(bold("\n  paste each flag, blank line to skip one\n"))
        for i in range(1, 6):
            try:
                supplied.append(input(f"  flag {i} > ").strip())
            except (EOFError, KeyboardInterrupt):
                print()
                return 1

    found = {f.strip() for f in supplied if f.strip()}
    hits = 0
    print()
    for i, flag in enumerate(expected, 1):
        if flag in found:
            hits += 1
            print(green(f"  [x] flag {i}  {flag}"))
        else:
            print(dim(f"  [ ] flag {i}  still buried"))
    print(f"\n  {bold(str(hits))}/5 dug out"
          + (green("  - lair cleared.") if hits == 5 else "") + "\n")
    return 0


# ------------------------------------------------------------------------ main

def main() -> int:
    parser = argparse.ArgumentParser(
        description="CipherHunt - a terminal hunt through eight ciphers.")
    parser.add_argument("--board", action="store_true", help="show progress and exit")
    parser.add_argument("--reset", action="store_true", help="wipe progress")
    parser.add_argument("--stage", type=int, metavar="N", help="jump to chamber N")
    parser.add_argument("--lair", nargs="?", const="lair", metavar="DIR",
                        help="build a dig site on disk to hunt with real shell tools")
    parser.add_argument("--verify", nargs="*", metavar="FLAG",
                        help="check the flags you pulled out of the lair")
    args = parser.parse_args()

    if args.reset:
        SAVE_PATH.unlink(missing_ok=True)
        print("progress wiped.")
        return 0
    if args.board:
        show_board(load_save(), build_chambers())
        return 0
    if args.lair:
        build_lair(Path(args.lair).expanduser().resolve())
        return 0
    if args.verify is not None:
        return verify_flags(list(args.verify))
    return run_hunt(args.stage)


if __name__ == "__main__":
    sys.exit(main())
