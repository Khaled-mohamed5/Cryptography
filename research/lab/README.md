# XXE lab

Reproduces every **[verified]** claim in [`../SSI-XXE-RESEARCH.md`](../SSI-XXE-RESEARCH.md).

Requires PHP ≥ 8, JDK ≥ 17 and Python 3. Everything runs against files these scripts
create under `tmp/`, and the collector binds to `127.0.0.1` only — **nothing leaves the
machine and nothing outside this directory is touched.** For authorised lab use.

## 1. Schemes, wrappers and source-code reads

```sh
php php_xxe_schemes.php
javac XxeSchemes.java && java XxeSchemes
```

Covers §3.1–§3.4 and §4. Expected highlights:

- a **bare path with no scheme** reads the file in both PHP and Java — the answer to
  "read files without `file://`";
- `php://filter/convert.base64-encode/resource=` reads source code; the same file read
  raw fails with `ParsePI: PI php never end`;
- `zip://` fails (`Fragment not allowed`) and `glob://` fails — use `phar://`;
- `netdoc:` is `unknown protocol` on any JDK ≥ 9;
- CDATA wrapping survives `<` and `>` but dies on `&`;
- `XInclude parse="text"` reads raw source with no DOCTYPE and no wrapper.

## 2. Blind XXE

Terminal 1:

```sh
python3 oob_collector.py
```

Terminal 2:

```sh
php blind_xxe.php
javac LocalDtdError.java && java LocalDtdError
cat hits.log
```

Covers §5.2–§5.5:

- the naive internal-subset payload fails with `PEReferences forbidden in internal subset`
  — the well-formedness constraint that forces every blind-XXE payload to use an external
  DTD;
- `hits.log` shows the out-of-band channel landing:
  `HIT /steal?d=U0VDUkVUX0ZMQUc9…` (`base64 -d` it);
- the error-based channel returns the file inside a `FileNotFoundException` (Java) or an
  `Invalid URI` message (libxml2);
- `LocalDtdError` also runs the on-disk-DTD variant against
  `/usr/share/xml/fontconfig/fonts.dtd`, which needs **no network at all**. If that file
  is absent, find another gadget with `find / -name '*.dtd'`.

The DTDs carry a `{{TARGET}}` placeholder that the collector substitutes with an absolute
`tmp/secret.txt` path at serve time. That is not cosmetic: inside a DTD fetched over HTTP
the base URI is the DTD's own URL, so a scheme-less path would be resolved against it and
fetched back from the attacker's server instead of the target's disk (§5.4).

## 3. Defences

```sh
php php_defaults.php
javac DefTest.java && java DefTest
```

Covers §6. The two lines that matter: Java's **default** `DocumentBuilderFactory` leaks,
and PHP only leaks when the application passes `LIBXML_NOENT`.

## Cleanup

```sh
rm -rf tmp hits.log *.class
```
