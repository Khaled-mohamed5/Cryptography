# SSI & XXE — assignment pack

Everything for the five assignment topics, plus a runnable lab for CVE-2019-0221.

## What's in here

| Path | What it is |
|---|---|
| `SSI-XXE-RESEARCH.md` | **The main report.** All five topics: 8 SSI CVEs, the SSI directives, XXE source-code reads, reading files without `file://`, and blind XXE. |
| `ssi-xxe.html` | The same report as a web page — open it in a browser. |
| `cve-2019-0221/` | **The runnable CVE lab.** Start with its `README.md`. |
| `lab/` | The XXE harnesses that produced the `[verified]` results in the report. |

## Just want to see the CVE demo?

```sh
cd cve-2019-0221
chmod +x *.sh
./setup.sh          # downloads Tomcat 9.0.17 + 9.0.19 (~22 MB, cached after)
./run.sh start
./exploit.sh
./run.sh stop
```

Needs `bash`, `curl`, `tar`, `python3` and a JDK. On Windows use WSL or Git Bash.
Both servers bind to `127.0.0.1` only.

## Want to see the XXE results reproduced?

```sh
cd lab
php php_xxe_schemes.php
javac XxeSchemes.java && java XxeSchemes
```

Needs PHP 8+ and a JDK. See `lab/README.md` for the blind-XXE part, which also
needs Python 3 for the loopback collector.

---

For authorised lab work and coursework only. Nothing here should be pointed at a
system you do not own or have written permission to test.
