# Lab setup

## VMs

Two guests, both snapshotted **before** installing Box Tools and again immediately after:

- **Windows 11** (or 10 22H2) — primary target. Most of the execution primitives are Windows-specific.
- **macOS** (VM or a spare machine) — the quarantine/Gatekeeper and code-signing findings live here.

Do the work in a VM with a clean snapshot you can roll back to. You will be launching things
that execute, and you want a known-good baseline to diff against.

## Accounts

Use two Box accounts: a **victim** account (Box Tools installed, signed in) and an
**attacker** account that shares a folder with the victim. Almost every P1 finding —
malicious filename, hostile extension, missing MOTW — is realistic only through the
"collaborator shares a folder" path, so set it up from the start and demo it that way.

## Capture the install

Before installing, start:

- **Procmon** with a filter on `Path contains Box` — captures every file and registry write,
  which tells you where the token lands, where the cache is, and what ACLs are set.
- **Autoruns** — snapshot before and after, diff it, and you have every persistence point
  the installer created.

On macOS:

```bash
sudo fs_usage -w -f filesystem | grep -i box       # during install
```

Then, after install:

```bash
pkgutil --pkgs | grep -i box
pkgutil --files <pkg-id>
```

## Intercepting the loopback protocol

Plain HTTP on a fixed loopback port. Three approaches, in order of effort:

### 1. Passive capture (start here)

**Windows** — Npcap with "Support loopback traffic" enabled, then Wireshark on
*Adapter for loopback traffic capture*:

```
tcp.port == 17223 || tcp.port == 17224
```
Right-click a packet → Follow → HTTP Stream to read whole request/response pairs.

**macOS**:
```bash
sudo tcpdump -i lo0 -A -s0 'tcp port 17223 or tcp port 17224'
```

### 2. Man-in-the-middle proxy (to *modify* traffic)

The server binds the fixed port, so you have to displace it:

1. Stop `Box Local Com Server` (and Box Edit).
2. Start a reverse proxy on 17223 that forwards to 17225.
3. Restart the com server forced onto 17225 — easiest by occupying 17223 first so it takes
   the fallback, then repeating with 17224 occupied too, or by patching its config.

```bash
mitmproxy --mode reverse:http://127.0.0.1:17225 --listen-port 17223
```

This gives you request rewriting, which you need for parameter fuzzing at scale.

### 3. Instrumentation (most reliable, if the runtime allows)

```bash
frida-trace -p <pid> -i "*ecv*" -i "*rigin*" -i "*ost*"
```

Hook the request handler and the origin comparison directly. If the binary is Electron or
.NET (§3 of the README), skip all of this and read the source.

## Static analysis

```bash
# what is it built with?
strings -n 8 "Box Local Com Server.exe" | grep -Ei "electron|node_modules|asar|mscorlib|Qt5|Qt6|openssl"

# Electron -> read the actual JS
npx asar extract resources/app.asar out/
grep -rniE "origin|referer|127\.0\.0\.1|localhost|allowlist|whitelist|extension" out/ | head -50

# .NET -> dnSpy / ILSpy, then find the request handler and the origin check

# native -> Ghidra; search for the string "app.box.com" and cross-reference it,
# that lands you on the origin validation in one step
```

Also worth pulling out of any build:

```bash
strings -n 6 <binary> | grep -Ei "\.exe$|\.bat$|\.hta$|\.lnk$|blocked|denied|forbidden"
```
An embedded extension blocklist is often sitting there in the clear. Once you have the list,
you know exactly which extensions to attack around the edges (§P1.1).

## Windows: reading the security posture quickly

```powershell
Get-Process | Where-Object { $_.Name -like "*Box*" } | Select Name, Id, Path
Get-NetTCPConnection -LocalPort 17223,17224 -ErrorAction SilentlyContinue |
    Select LocalAddress, LocalPort, State, OwningProcess
Get-Service | Where-Object { $_.DisplayName -like "*Box*" }
icacls "C:\Program Files\Box" /T /C 2>$null | Select-String -Pattern "(Users|Everyone|Authenticated Users):\(.*[WMF]"
```

`tools/win_lpe_audit.ps1` runs all of this plus the DACL and DLL-hijack checks.

## macOS: same

```bash
lsof -nP -iTCP:17223 -sTCP:LISTEN
launchctl list | grep -i box
ls -la@ ~/Library/Application\ Support/Box/Box\ Edit/
codesign -dvvv --entitlements - ~/Library/Application\ Support/Box/Box\ Edit/Box\ Edit.app 2>&1
```

`tools/check_macos.sh` runs all of this.
