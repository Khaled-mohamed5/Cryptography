# ORB-04 — `NEVER_FAIL` build path emits a forged signature and exits successfully

**Severity:** Informational (latent — not enabled in the shipped build)
**Asset:** `worldcoin/orb-secure-element`
**Component:** `orb-secure-element.c:409-421, 499-512, 534-547`

## Detail

`orb-sign-iris-code` and `orb-sign-attestation` sign a SHA-256 digest with the
SE050. Three failure paths are compiled differently under `-DNEVER_FAIL`:

```c
#ifdef NEVER_FAIL
    LOG_E("Failed to sign digest, err: %x, printing a pre-defined signature");
    printf("eeeeeeee...eee");
    ret = EXIT_SUCCESS;
#else
    ret = EXIT_SIGN_FAILED;
#endif
```

The same pattern covers the SE050 timeout (`"ffff..."`) and keystore lock
failure (`"dddd..."`). In each case the tool writes a constant to stdout and
exits `0` — the exact contract a caller checking the exit code relies on to
decide that an iris code or attestation was genuinely signed by the secure
element.

**This is currently not exploitable.** `CMakeLists.txt` never defines
`NEVER_FAIL`, and it is not referenced anywhere else in the repository, so
shipped binaries take the `#else` branches.

## Why it is still worth removing

The macro converts a hardware-signing failure into a silent success, and the
only thing standing between that and production is the absence of one
`-D` flag. A debug convenience with that blast radius is better expressed as a
separate test harness than as a preprocessor branch inside the signing tool.

## Remediation

Delete the `NEVER_FAIL` branches. If a stub is needed for bring-up, build a
separate mock binary, or at minimum have the stub exit non-zero and write to
stderr so no caller can mistake it for a real signature.
