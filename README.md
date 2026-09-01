 Cryptography in Java

This repository contains a basic implementation of the **Data Encryption Standard (DES)** algorithm using Java.

The code demonstrates:

- Key scheduling (PC-1, left shifts, PC-2)
- Initial and Final Permutations
- One Feistel round including:
  - Expansion (E-box)
  - XOR with subkey
  - S-Box substitution
  - P-Permutation
- Manual round logic written from scratch (without crypto libraries)

 Files Included

- `Main.java` – main class to run the DES round
- `DES.java` – core logic (Feistel function, expansion, S-Box, etc.)
- `DESKEY.java` – handles subkey generation
- `PLAINTEXT.java` – handles initial and final permutations

 Why this project?

This project is for educational purposes to understand how DES works under the hood.

# Author

Khaled Mohamed  
Ahmed Shawkat
Computer Science Student – Cairo University  

---

# CipherHunt

A terminal hunt that sits next to the DES code, for practising the other half
of cryptography: breaking it, at a prompt, with the tools already on the machine.

```bash
python3 cipherhunt.py          # start the hunt (progress is saved, resume any time)
python3 cipherhunt.py --board  # see how far you got
python3 cipherhunt.py --lair   # build a dig site to hunt with real shell tools
```

No dependencies. Python 3.8+.

## Eight chambers

Each chamber shows a ciphertext and hides one word. Speak the word, the door
opens. Two hints per chamber, 25 points each, and `tools` is always free.

| # | Chamber | What breaks it |
|---|---------|----------------|
| 1 | The Scratched Lintel | Caesar shift, brute force all 25 |
| 2 | The Padded Door | base64, and look again after the first pass |
| 3 | The Mirrored Slab | hex decode, then reverse |
| 4 | The Single Key | single byte XOR, 256 keys ranked by English |
| 5 | The Repeating Key | Vigenere, with a key chamber 4 handed you |
| 6 | The Sphinx's Alphabet | substitution, cracked by letter frequency |
| 7 | The Feistel Gate | raw bits, the dialect `Main.stringToBinary` speaks |
| 8 | The Reused Pad | key reuse: `A^B` XOR `A` gives up `B`, no key needed |

Chamber 8 is the one that matters outside a game. Reusing a keystream is a real
failure mode, and the break needs no key at all.

## Toolbelt

Type these at any prompt: `caesar` `rot13` `b64` `hex` `bits` `xor` `xorkey`
`vig` `freq` `rev` — plus `hint`, `tools`, `board`, `status`, `skip`, `quit`.

`tools` also prints the shell equivalent of each one (`base64 -d`, `xxd -r -p`,
`tr 'A-Za-z' 'N-ZA-Mn-za-m'`, `fold -w1 | sort | uniq -c | sort -rn`), which is
the actual point of the exercise.

## The lair

`--lair` writes a dig site to disk with five flags in it, hidden behind `grep`,
`find`, `strings`, `base64` and `cat`. No script needed for any of them — one
shell command each, if you pick the right one. Start with
`cat lair/camp/START.txt`, and check your haul with:

```bash
python3 cipherhunt.py --verify
```

A blunt `grep -rn 'HUNT{' .` finds exactly one of the five. Working out why the
other four escape it is the lesson.
