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
