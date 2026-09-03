# ORB-05 — Memory-handling hygiene in `orb-secure-element.c`

**Severity:** Informational
**Asset:** `worldcoin/orb-secure-element`

None of these are attacker-reachable — the tool reads a 32-byte digest from
stdin behind a seccomp allowlist and `PR_SET_NO_NEW_PRIVS` — but they are worth
tidying.

## 1. BIO leak on the error path (`read_digest`, lines 275-313)

`b64 = BIO_new(BIO_f_base64())` is pushed onto the chain, but the `err:` label
returns without `BIO_pop`/`BIO_free`. Every malformed-input rejection leaks the
BIO. The process exits immediately afterwards, so the leak is bounded, but the
success path frees it and the error path should match.

## 2. Unreachable label (`prepare_host_eckey`, line 166)

`free_DEC_session_key:` has no `goto` targeting it — the `Rmac` allocation at
line 159 jumps to `free_MAC_session_key` on failure. Dead code that looks like
it should be live; either wire it up or remove it.

## 3. Non-void function with no return (line 53)

```c
int __attribute__((weak)) delete_old_pairing_keys()
{};
```

Falling off the end of a non-`void` function is undefined behaviour, and the
empty statement `{}` followed by `;` is a further oddity. The return value is
never used (`orb-secure-element.c:551`), so the function should be `void`.

## 4. `print_signature` sets the close flag on the wrong BIO (line 345)

`BIO_new_fp(f, BIO_NOCLOSE)` creates the file BIO, then `bio_out` is reassigned
to the base64 BIO by `BIO_push`. `BIO_set_close(bio_out, 1)` therefore sets the
flag on the base64 BIO rather than the file BIO, so the comment
("Tell BIO to close stdout on BIO_free_all()") does not describe what happens.
Harmless here since the process is exiting.

## 5. Documented interface does not match the code (lines 6, 485-497)

The header comment states "The tool accepts no command line arguments", but
`main` accepts the digest as `argv[1]`. Worth reconciling so callers do not
assume stdin is the only input channel.
