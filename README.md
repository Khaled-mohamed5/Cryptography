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

# Poste Restante

`poste-restante/` is a separate, self-contained project in this repository: a
blind dead-drop board where anyone can leave a message under a cover name and
style its envelope with their own CSS. It is a study in the other half of
applied cryptography — not the cipher, but everything around it: anonymous
identity that maps to nothing, untrusted content rendered without trusting it,
and abuse handling that does not require knowing who anyone is.

Python 3, standard library only:

```sh
cd poste-restante
python3 app.py                                    # http://127.0.0.1:8080
python3 -m unittest discover -s tests -t tests
```

See `poste-restante/README.md` for the threat model and what the station
refuses to carry.

# Author

Khaled Mohamed  
Ahmed Shawkat
Computer Science Student – Cairo University  
