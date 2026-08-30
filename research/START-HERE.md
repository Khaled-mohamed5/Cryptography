# SSI & XXE — assignment pack

Everything for the five assignment topics, plus a runnable lab for CVE-2019-0221.

## What's in here

| Path | What it is |
|---|---|
| `SSI-XXE-RESEARCH.md` | **The main report.** All five topics: 8 SSI CVEs, the SSI directives, XXE source-code reads, reading files without `file://`, and blind XXE. |
| `ssi-xxe.html` | The same report as a web page — open it in a browser. |
| `cve-2024-3788/` | **SSI injection lab (CWE-97).** Stored input becomes an `#exec` directive and the server runs it. Pure SSI. |
| `cve-2019-0221/` | **Tomcat SSI `printenv` lab.** An XSS bug inside an SSI command. |
| `lab/` | The XXE harnesses that produced the `[verified]` results in the report. |

## Just want to see SSI injection execute a command?

```sh
cd cve-2024-3788
chmod +x *.sh
./setup.sh && ./run.sh start && ./exploit.sh
```

Needs Apache with `mod_include` (`sudo apt install apache2`) plus `python3` and `curl`.

## The Tomcat CVE demo

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
