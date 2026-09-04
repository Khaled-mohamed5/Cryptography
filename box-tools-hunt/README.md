# Box Tools — Vulnerability Hunting Playbook

Target: **Box Tools** (installer bundle containing *Box Edit* + *Box Local Com Server*),
listed as an in-scope, bounty-eligible asset with a **Critical** max severity and no
reports filed yet.

> Scope note: everything here targets **your own machine, your own Box account, in a VM
> you own.** Do not point any of it at another user, another tenant, or Box production
> infrastructure beyond what your own client does normally.

---

## 1. What the product actually is

Box Tools is the local half of a browser↔desktop bridge. You click "Open" on a file in
the Box web app, and a **locally installed HTTP server** receives the instruction,
downloads the file, drops it in a cache folder, and hands it to whatever desktop
application the OS associates with that extension. When you save, it uploads the file back.

That sentence contains four separate execution primitives. This is why the asset is rated
Critical and why it is worth real time.

### Components

| Platform | Component | Location |
|---|---|---|
| Windows | `Box Edit.exe` | `%LOCALAPPDATA%\Box\Box Edit\` |
| Windows | Download/edit cache | `%LOCALAPPDATA%\Box\Box Edit\Documents\` |
| Windows | `Box Local Com Server` | `%LOCALAPPDATA%\Box\Box Local Com Server\` **or** `C:\Program Files\Box\Box Local Com Server\` (depends on install mode) |
| macOS | `Box Edit.app`, `Box Local Com Server.app` | `~/Library/Application Support/Box/Box Edit/` |
| macOS | Startup | LaunchAgent / login item |

### The transport — the core of the attack surface

The browser talks to the local server over **plaintext HTTP on `127.0.0.1:17223`**, falling
back to **`17224`** if 17223 is taken. The documented request shape is:

```
http://127.0.0.1:17223/application_request?application=BoxEdit&com=<identifier>&timeout=<ms>&ms=<timestamp>
```

Two consequences fall straight out of that:

1. **Fixed port, plaintext HTTP, browser-reachable.** Every website your victim visits can
   send requests to that port. The only thing standing between `evil.com` and the local
   server is whatever origin/authentication check the server implements. Finding that check
   to be absent, weak, or bypassable is the whole game.
2. **Any local process can also talk to it**, and can sniff the loopback traffic. That is
   your fastest route to learning the protocol (§3).

---

## 2. Bug classes, ranked

Ranked by (probability this specific product has it) × (what Box will pay for it).
Work them top-down. Do not start with LPE — start with P0.

### P0 — Drive-by RCE through the local server

This is the crown jewel and the reason to hunt this asset.

**P0.1 — Missing or weak Origin validation (CSRF against localhost)**

The key insight: a plain `GET` with no custom headers is **not preflighted**. Even if the
browser blocks `evil.com` from *reading* the response, the request still reaches the server
and the **side effect still fires**. If the server acts on a request without verifying the
Origin, a random web page can drive Box Edit.

Test, in order:
- Does the server require `Origin: https://app.box.com`? Send with no Origin at all (curl),
  with `https://evil.com`, with `null` (sandboxed iframe / `data:` URL).
- Is the check a substring match? Try `https://app.box.com.evil.com`,
  `https://evilapp.box.com`, `https://app.box.com@evil.com`, `https://app-box.com`.
- Is it only checked on `OPTIONS` but not on the actual request?
- Does it reflect an arbitrary `Origin` back in `Access-Control-Allow-Origin` with
  `Access-Control-Allow-Credentials: true`?
- Does it only check `Referer`, which can be suppressed via `Referrer-Policy: no-referrer`?

`tools/origin_test.html` automates this. Critically, it distinguishes **readability** from
**side effect** — report the side effect even when the response is unreadable.

**P0.2 — DNS rebinding**

If the server validates only the `Host` header (or nothing), rebinding defeats it: register
a host that resolves first to your IP, then to `127.0.0.1`, and `http://rebind.attacker.com:17223`
becomes *same-origin* — full read access, no CORS involved. Check whether the server rejects
any `Host` other than `127.0.0.1`/`localhost`. If it accepts `Host: rebind.attacker.com`, that
is a finding on its own even before you build the rebinder.

**P0.3 — The `com=` parameter: is it a secret?**

Determine what `com=` actually is. Capture 20+ real requests (§3) and look at it:
- Constant across sessions? → not a secret, no CSRF protection at all.
- Derived from `ms=` / a timestamp? → predictable.
- High-entropy per-session token? → then find where the *browser* gets it. If `app.box.com`
  JS fetches it from the local server itself over an unauthenticated endpoint, the token is
  not a defense — `evil.com` can fetch it the same way (subject to P0.1).
- Short? → brute-forceable; the local server has no rate limit and no lockout.

**P0.4 — Attacker-controlled download source**

Map every parameter the server accepts. If any of them carries a URL, host, path, or file
identifier that the server fetches, ask:
- Can it be pointed at `http://attacker.com/payload`? → attacker-controlled bytes written to
  disk and opened. Immediate RCE chain.
- Can it be pointed at internal hosts? → SSRF from inside the victim's network, which is a
  finding in its own right.
- Can it be pointed at a UNC path (`\\attacker\share\x`) on Windows? → NTLM credential leak
  plus remote file execution.

### P1 — Execution primitives (chain these onto P0)

**P1.1 — Extension handling / blocklist bypass**

Box Edit resolves the file's extension to the OS default handler and launches it. The only
control possible here is a blocklist, and blocklists leak. Build a folder in your own Box
account and try to open each of these through the normal flow:

```
.exe .com .scr .bat .cmd .pif .msi .msc .cpl .hta .lnk .url .scf .reg .chm
.wsf .wsh .js .jse .vbs .vbe .ps1 .psm1 .jar .py .pyw .iso .img .vhd .vhdx
.appref-ms .diagcab .settingcontent-ms .library-ms .search-ms .theme
```

Then attack the *parser*, not the list:
- trailing dot or space: `payload.exe.` / `payload.exe ` (Windows strips them)
- double extension: `invoice.pdf.exe`
- case: `.ExE`, `.LNK`
- RTLO unicode: `invoice\u202Egnp.exe`
- NTFS stream suffix: `payload.txt::$DATA`
- no extension at all, but a shebang / magic bytes
- macOS: `.command`, `.terminal`, `.workflow`, `.app` (a directory — does it sync as a bundle?),
  `.dmg`, `.pkg`, `.webloc`, `.inetloc`

**P1.2 — Missing Mark-of-the-Web / quarantine flag** ← *high hit-rate, often overlooked*

Any tool that downloads a file from the internet and opens it must tag it as untrusted.

- **Windows:** the cached file must carry a `Zone.Identifier` alternate data stream with
  `ZoneId=3`. Without it, `.docm`/`.xlsm` open **without Protected View** — macros are one
  click away instead of behind two barriers. `.hta`, `.js`, `.chm` lose their warning dialogs
  entirely.
- **macOS:** the file must carry the `com.apple.quarantine` extended attribute. Without it,
  **Gatekeeper never evaluates it** — an unsigned `.app`, `.dmg`, or `.command` from a shared
  folder launches with no prompt.

Run `tools/check_motw.ps1` / `tools/check_macos.sh` right after opening a file. This is a
clean, self-contained High even without a P0 chain, because Box folders are shared between
users — a collaborator dropping a file in a shared folder is a realistic attacker.

**P1.3 — Path traversal in the file name**

The server builds a local path from the Box file name. That name is fully attacker-controlled
if the attacker can share a folder with the victim. Upload files named:

```
..\..\..\..\x.lnk
....\\....\\x.lnk
..%2f..%2fx.lnk
/../../x.lnk
C:\Users\Public\x.lnk
\\attacker.tld\share\x
../../../../Library/LaunchAgents/com.evil.plist     (macOS)
```

Target for Windows: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\` → RCE at next
login. Target for macOS: `~/Library/LaunchAgents/`. Note the Box *web* API may itself reject
these names — try creating them through the API directly, and via a folder name rather than a
file name, and via the upload `Content-Disposition` filename.

**P1.4 — Save-back / upload path**

After editing, the file goes back up. Check whether the destination file id is taken from the
local request (attacker-controllable → overwrite an arbitrary file the victim can write, or
write into a folder the victim owns) or is bound server-side to the original download.

### P2 — Local privilege escalation & persistence

Only worth reporting where a **privilege boundary is actually crossed.** A per-user install in
`%LOCALAPPDATA%` being writable by that same user is not a vulnerability — do not report it.

- **Per-machine install** puts the com server in `C:\Program Files\Box\`. If it runs as a
  service or as SYSTEM: check the service DACL (`sc sdshow`), unquoted binary path, directory
  and file ACLs, and DLL search-order hijacking (a missing DLL loaded from a writable directory).
  `tools/win_lpe_audit.ps1` automates the sweep.
- **Updater.** Is the update manifest fetched over HTTPS? Is the downloaded binary signature-
  verified before execution? An updater that runs elevated and does not verify a signature is a
  Critical. MITM your own VM with a proxy and a trusted CA to test the transport; separately,
  swap the downloaded binary on disk before execution to test the signature check.
- **Symlink / junction abuse** on the cache directory if any privileged process writes there.
- **macOS:** `Box Edit.app` lives in a user-writable directory. That is fine per-user — the
  finding only exists if something *privileged* (a LaunchDaemon, a `SMJobBless` helper, an
  installer script) launches or trusts that path. Check for a privileged helper first. Also run
  `codesign -dvvv --entitlements -` on both bundles: look for `get-task-allow`, a missing
  hardened runtime, or `disable-library-validation` → dylib injection into a process holding
  Box credentials.

### P3 — Credential and transport handling

- **Where does the auth token live?** Grep the install and cache directories, the registry, and
  (macOS) whether it uses the Keychain or a plist. A plaintext OAuth token on disk readable by
  other local accounts is a solid Medium–High.
- **TLS validation** on the desktop→Box API connection. Accepting a *user-installed* CA is
  normal and not a bug; accepting an **invalid or mismatched** certificate is.
- Plaintext loopback HTTP is inherent to the design and likely already accepted — do not report
  it alone.

---

## 3. Learn the protocol before you fuzz it

Do not guess the API. Capture it. It is plaintext HTTP on loopback, so this is easy and it is
the single highest-leverage hour you will spend on this target.

**Windows** — install Npcap with loopback capture, then in Wireshark select the
`Adapter for loopback traffic capture` and filter:
```
tcp.port == 17223 || tcp.port == 17224
```
**macOS**:
```bash
sudo tcpdump -i lo0 -A -s0 'tcp port 17223 or tcp port 17224'
```

Now exercise every feature in the Box web UI — open a file, edit, save, close, open a second
file, open an unsupported type — and record every request/response pair. You now have the real
API surface instead of a documented example.

**Then check what the binaries are built with**, because it decides your whole approach:

```bash
# Windows
strings -n 8 "Box Local Com Server.exe" | grep -Ei "electron|node_modules|asar|\.pdb|mscorlib|Qt"
# macOS
otool -L "Box Local Com Server.app/Contents/MacOS/"* 2>/dev/null | head -40
ls "Box Edit.app/Contents/Resources/" | grep -i asar
```

- **Electron** → `npx asar extract app.asar out/` and read the origin-check code directly.
- **.NET** → open it in dnSpy/ILSpy. Same outcome.
- **Native C++/Qt** → fall back to Ghidra, or stay black-box with §4 tooling.

If it is Electron or .NET, stop black-boxing and go read the validation function. You will find
the bypass in the source instead of guessing at it.

---

## 4. Tooling in this folder

| File | Purpose |
|---|---|
| `tools/probe_com_server.py` | Enumerates the local server: paths, methods, Origin/Host handling, CORS headers, WebSocket upgrade. Run this first. |
| `tools/origin_test.html` | Serve from a non-Box origin. Separates *readable response* from *side effect fired* — the distinction that makes or breaks the P0.1 report. |
| `tools/check_motw.ps1` | Windows: verifies Zone.Identifier on cached files, dumps ACLs and traversal-escape checks. |
| `tools/check_macos.sh` | macOS: quarantine xattr, code signature and entitlements, LaunchAgents/Daemons, bundle permissions, listening sockets. |
| `tools/win_lpe_audit.ps1` | Windows: services, DACLs, unquoted paths, DLL hijack candidates, autoruns for Box components. |

See `lab-setup.md` for the VM and interception setup.

---

## 5. Suggested order of work

1. Build the VM, snapshot clean, install Box Tools, snapshot again.
2. Capture the loopback protocol (§3). Write down every endpoint and parameter.
3. Identify the runtime (Electron/.NET/native). If readable, read the origin check.
4. Run `probe_com_server.py`. Any request that works with no `Origin` or a foreign `Origin` → go straight to `origin_test.html` and build the drive-by PoC.
5. In parallel (these are independent of P0 and each is reportable alone): the MOTW/quarantine check, the extension matrix, the traversal filenames.
6. Only then the LPE sweep.

---

## 6. Before you submit

**Things that will be closed as Informative — don't send them:**
- "A local HTTP server is listening on 127.0.0.1" with no bypass demonstrated.
- Anything requiring local admin, physical access, or pre-existing code execution.
- The per-user install directory being writable by that same user.
- Missing security headers on a localhost endpoint with no impact shown.
- Plaintext HTTP on loopback, on its own.
- Findings from a modified/patched client attacking itself.

**What makes a Critical actually land:**
- A single HTML file, hosted on an ordinary origin, that a victim visits with Box Tools running
  and their normal Box session, which results in code execution with no further interaction —
  or with one realistic click that is not "please run this exe."
- A short video: clean VM → open the page → calculator/notepad spawns. Show the URL bar.
- Exact versions: Box Tools version, OS build, browser and version.
- The reasoning about *why* the control failed, not just that it did. If you read the origin
  check in the source, quote it.

**Report skeleton:**

```
## Summary
Any website can [action] because the Box Local Com Server on 127.0.0.1:17223
accepts requests with [no Origin header / an arbitrary Origin], leading to [impact].

## Affected component and version
Box Tools <version>, <OS build>, <browser>

## Steps to reproduce
1. Install Box Tools and sign in to Box in the browser.
2. Host the attached PoC on any origin and visit it.
3. Observe <concrete outcome>.

## Impact
<Attacker capability, in one paragraph. State the pre-conditions honestly —
"victim has Box Tools installed and running" is a fair one; "victim has already
run attacker code" is not.>

## Proof of concept
<the HTML file + the exact request it sends + video>

## Suggested remediation
<origin allowlist + a per-session token bound to the Box session, MOTW tagging,
canonicalise the filename before joining paths, etc.>
```

---

## Sources

- [Understanding System Requirements to Use Box Tools v4 — Box Support](https://support.box.com/hc/en-us/articles/360043697634-Understanding-System-Requirements-to-Use-Box-Tools-v4)
- [Large Scale Deployments: Box Tools — Box Support](https://support.box.com/hc/en-us/articles/360043695834-Large-Scale-Deployments-Box-Tools)
- [Box Tools/Edit Frequently Asked Questions — Box Support](https://support.box.com/hc/en-us/articles/360044195453-Box-Tools-Edit-Frequently-Asked-Questions)
- [Unable to Use Box Edit with Certain File Type — Box Support](https://support.box.com/hc/en-us/articles/360044192693-Unable-to-Use-Box-Edit-with-Certain-File-Type)
- [Box Edit.exe process details — file.net](https://www.file.net/process/box%20edit.exe.html)
- [Box Local Com Service.exe process details — file.net](https://www.file.net/process/box%20local%20com%20service.exe.html)
- [Deploy Box Tools at Scale — Marriott Library, University of Utah](https://apple.lib.utah.edu/box-tools-installer-solution/)
- [Box Tools downloads](https://www.box.com/resources/downloads)
