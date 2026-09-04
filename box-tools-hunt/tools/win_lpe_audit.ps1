<#
.SYNOPSIS
    Box Tools — Windows local privilege escalation surface audit.

.DESCRIPTION
    Only reports conditions where a privilege boundary is actually crossed. A per-user
    install under %LOCALAPPDATA% being writable by that same user is normal and is NOT a
    finding — do not report it. What matters is a component that runs elevated (a service,
    a scheduled task running as SYSTEM, an elevated updater) whose binary, directory, or
    DLL search path a standard user can influence.

    Read-only. Run as a standard user for the honest answer, since that is the attacker's
    position.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\win_lpe_audit.ps1
#>

$ErrorActionPreference = 'SilentlyContinue'
function Write-Head($t) { Write-Host "`n=== $t ===" -ForegroundColor Cyan }
function Write-Hit($t)  { Write-Host "  [!] $t" -ForegroundColor Red }
function Write-Ok($t)   { Write-Host "  [ok] $t" -ForegroundColor Green }

$me = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = ([Security.Principal.WindowsPrincipal]$me).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "Running as $($me.Name)  (admin: $isAdmin)"
if ($isAdmin) { Write-Host "  Re-run as a standard user — findings only count from an unprivileged context." -ForegroundColor Yellow }

# ---------------------------------------------------------------- services
Write-Head "Box services"
$svcs = Get-CimInstance Win32_Service | Where-Object { $_.Name -like "*Box*" -or $_.PathName -like "*\Box\*" }
if (-not $svcs) { Write-Host "  No Box services — likely a per-user install, so no service LPE surface." }
foreach ($s in $svcs) {
    Write-Host "`n  $($s.Name)  [$($s.State)]  runs as: $($s.StartName)"
    Write-Host "    path: $($s.PathName)"

    # Unquoted service path with a space -> a planted binary earlier in the path wins.
    if ($s.PathName -notmatch '^"' -and $s.PathName -match '^[^"]*\s[^"]*\\') {
        Write-Hit "Unquoted binary path containing spaces — classic hijack if any parent dir is writable."
    }

    # Service DACL: can a normal user reconfigure it?
    $sd = & sc.exe sdshow $s.Name 2>$null
    if ($sd -match 'A;;[^;]*(WP|DC|WD|SD|WO)[^;]*;;;(AU|IU|BU|WD)') {
        Write-Hit "Service DACL grants configuration rights to non-admin principals: $sd"
    }

    # Binary and directory ACLs.
    $bin = ($s.PathName -replace '^"([^"]+)".*$', '$1') -replace '^([^\s]+\.exe).*$', '$1'
    if (Test-Path $bin) {
        $dir = Split-Path $bin
        foreach ($target in @($bin, $dir)) {
            (Get-Acl $target).Access |
              Where-Object { $_.IdentityReference -match 'Everyone|BUILTIN\\Users|Authenticated Users|INTERACTIVE' -and
                             $_.FileSystemRights -match 'Write|Modify|FullControl|CreateFiles' -and
                             $_.AccessControlType -eq 'Allow' } |
              ForEach-Object { Write-Hit "$target writable by $($_.IdentityReference) : $($_.FileSystemRights)" }
        }
    }
}

# ---------------------------------------------------------------- install dirs
Write-Head "Install directory permissions"
$dirs = @("C:\Program Files\Box", "C:\Program Files (x86)\Box", "C:\ProgramData\Box")
foreach ($d in $dirs) {
    if (-not (Test-Path $d)) { continue }
    Write-Host "  $d"
    Get-ChildItem $d -Recurse -Directory -ErrorAction SilentlyContinue |
      ForEach-Object {
        (Get-Acl $_.FullName).Access |
          Where-Object { $_.IdentityReference -match 'Everyone|BUILTIN\\Users|Authenticated Users' -and
                         $_.FileSystemRights -match 'Write|Modify|FullControl' -and
                         $_.AccessControlType -eq 'Allow' } |
          ForEach-Object { Write-Hit "$($_.IdentityReference) has $($_.FileSystemRights) — a machine-wide dir writable by a standard user" }
      }
}

# ---------------------------------------------------------------- DLL hijacking
Write-Head "DLL search-order candidates"
Write-Host "  Confirm these with Procmon: filter Result='NAME NOT FOUND' and Path ends with '.dll'"
Write-Host "  while restarting the Box process. Any miss resolved from a writable directory is the bug."
$boxExes = Get-ChildItem -Path @("C:\Program Files\Box","$env:LOCALAPPDATA\Box") -Recurse -Filter *.exe -ErrorAction SilentlyContinue
foreach ($e in $boxExes) { Write-Host "    $($e.FullName)" }

Write-Host "`n  Writable directories on the system PATH (a hijack lands here):"
$env:PATH -split ';' | Where-Object { $_ } | ForEach-Object {
    $p = $_.Trim()
    if (Test-Path $p) {
        $writable = (Get-Acl $p).Access | Where-Object {
            $_.IdentityReference -match 'Everyone|BUILTIN\\Users|Authenticated Users' -and
            $_.FileSystemRights -match 'Write|Modify|FullControl' -and $_.AccessControlType -eq 'Allow' }
        if ($writable) { Write-Hit "PATH entry writable by standard users: $p" }
    }
}

# ---------------------------------------------------------------- persistence / updater
Write-Head "Autostart entries and updater"
Get-CimInstance Win32_StartupCommand | Where-Object { $_.Command -like "*Box*" } |
    ForEach-Object { Write-Host "  [$($_.Location)] $($_.Name) -> $($_.Command)" }

Get-ScheduledTask | Where-Object { $_.TaskName -like "*Box*" -or $_.TaskPath -like "*Box*" } | ForEach-Object {
    $principal = $_.Principal.UserId
    Write-Host "  task: $($_.TaskName)  runs as: $principal  (level: $($_.Principal.RunLevel))"
    if ($_.Principal.RunLevel -eq 'Highest' -or $principal -match 'SYSTEM') {
        Write-Hit "Elevated scheduled task — check whether its action path or arguments are user-influenced."
    }
}

Write-Head "Updater checklist (manual)"
@(
 "Is the update manifest fetched over HTTPS with certificate validation?  -> MITM your own VM to test."
 "Is the downloaded installer Authenticode-verified BEFORE it is executed? -> swap the file on disk between"
 "  download and execution (Procmon gives you the window) and see if it still runs."
 "Does the updater run elevated? An elevated updater with no signature check is a Critical."
 "Is the download written to a world-writable directory before elevation?"
) | ForEach-Object { Write-Host "  - $_" }

Write-Host "`nDone.`n" -ForegroundColor Cyan
