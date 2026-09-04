<#
.SYNOPSIS
    Box Tools — Mark-of-the-Web and cache-directory audit (Windows).

.DESCRIPTION
    Box Edit downloads a file from the internet and hands it to a local application.
    Windows expects any such file to carry a Zone.Identifier alternate data stream with
    ZoneId=3 ("Internet"). That stream is what makes Office open a document in Protected
    View and what makes .hta / .js / .chm show a warning first.

    If it is missing, a .docm that a collaborator dropped into a shared Box folder opens
    with macros one click away instead of behind Protected View. That is a self-contained
    finding — no other bug needed to chain it.

    This script is read-only. It reports; it changes nothing.

.EXAMPLE
    # 1. Run once to snapshot the cache.
    # 2. Open a file from Box in the browser (ideally a .docm shared by a second account).
    # 3. Run again and compare.
    powershell -ExecutionPolicy Bypass -File .\check_motw.ps1
#>

$ErrorActionPreference = 'SilentlyContinue'

function Write-Head($text) { Write-Host "`n=== $text ===" -ForegroundColor Cyan }
function Write-Hit($text)  { Write-Host "  [!] $text" -ForegroundColor Red }
function Write-Ok($text)   { Write-Host "  [ok] $text" -ForegroundColor Green }

$cacheRoots = @(
    "$env:LOCALAPPDATA\Box\Box Edit\Documents",
    "$env:LOCALAPPDATA\Box\Box Edit",
    "$env:LOCALAPPDATA\Box\Box Local Com Server",
    "$env:APPDATA\Box"
)

Write-Head "Box directories present"
$live = @()
foreach ($root in $cacheRoots) {
    if (Test-Path $root) { Write-Host "  $root"; $live += $root }
}
if (-not $live) {
    Write-Hit "No Box directories found. Is Box Tools installed for this user?"
    return
}

# ---------------------------------------------------------------- MOTW
Write-Head "Mark-of-the-Web on cached files"
$files = Get-ChildItem -Path $live -Recurse -File -ErrorAction SilentlyContinue |
         Where-Object { $_.Length -gt 0 } | Select-Object -First 400

if (-not $files) {
    Write-Host "  Cache is empty. Open a file from the Box web app, then re-run."
} else {
    $missing = @(); $tagged = @()
    foreach ($f in $files) {
        $zone = Get-Content -Path $f.FullName -Stream Zone.Identifier -ErrorAction SilentlyContinue
        if ($zone) { $tagged += $f } else { $missing += $f }
    }
    Write-Host ("  tagged: {0}   untagged: {1}" -f $tagged.Count, $missing.Count)

    # Only files that actually came down from Box matter; anything in Documents\ did.
    $risky = $missing | Where-Object {
        $_.Extension -match '^\.(docm|xlsm|pptm|doc|xls|ppt|hta|js|jse|vbs|wsf|chm|iso|img|lnk|url|reg|ps1|jar|scr|exe|msi|cmd|bat)$'
    }
    foreach ($f in $risky) {
        Write-Hit "$($f.FullName)  — no Zone.Identifier on a $($f.Extension) file"
    }
    if ($risky.Count -gt 0) {
        Write-Host ""
        Write-Hit "Files downloaded from Box are not tagged as internet-origin."
        Write-Host "      Impact: Office macro files skip Protected View; scriptable types skip the" -ForegroundColor Yellow
        Write-Host "      execution warning. Reproduce with a .docm shared from a second Box account," -ForegroundColor Yellow
        Write-Host "      open it via Box Edit, and screenshot the absence of the Protected View bar." -ForegroundColor Yellow
    } elseif ($tagged.Count -gt 0) {
        Write-Ok "Cached files carry Zone.Identifier. Check the contents are actually ZoneId=3:"
        Get-Content -Path $tagged[0].FullName -Stream Zone.Identifier | ForEach-Object { Write-Host "      $_" }
    }
}

# ---------------------------------------------------------------- traversal escapes
Write-Head "Files written outside the cache root (path traversal evidence)"
$escapeTargets = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:USERPROFILE\Desktop",
    "$env:PUBLIC",
    "$env:TEMP"
)
$cut = (Get-Date).AddHours(-2)
foreach ($t in $escapeTargets) {
    $recent = Get-ChildItem -Path $t -File -ErrorAction SilentlyContinue |
              Where-Object { $_.CreationTime -gt $cut }
    foreach ($r in $recent) {
        Write-Hit "recent file in $t : $($r.Name)  ($($r.CreationTime))"
    }
}
Write-Host "  (Cross-reference against filenames you uploaded to Box with traversal sequences.)"

# ---------------------------------------------------------------- ACLs
Write-Head "Cache directory ACLs"
foreach ($root in $live) {
    Write-Host "  $root"
    (Get-Acl $root).Access |
        Where-Object { $_.IdentityReference -match 'Everyone|Users|Authenticated Users|INTERACTIVE' } |
        ForEach-Object { Write-Host "      $($_.IdentityReference) : $($_.FileSystemRights)" }
}

# ---------------------------------------------------------------- credentials on disk
Write-Head "Possible credential material on disk"
$hits = Get-ChildItem -Path $live -Recurse -File -Include *.json,*.xml,*.txt,*.cfg,*.config,*.ini,*.dat,*.log -ErrorAction SilentlyContinue |
        Select-String -Pattern 'access_token|refresh_token|"token"|Bearer |client_secret|api_key' -List -ErrorAction SilentlyContinue
foreach ($h in $hits) {
    Write-Hit "$($h.Path) : line $($h.LineNumber) matches $($h.Matches[0].Value)"
}
if (-not $hits) { Write-Ok "No obvious plaintext token strings in the scanned file types." }

# ---------------------------------------------------------------- listeners
Write-Head "Listening sockets"
Get-NetTCPConnection -LocalPort 17223,17224 -State Listen -ErrorAction SilentlyContinue | ForEach-Object {
    $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    Write-Host "  $($_.LocalAddress):$($_.LocalPort)  <- $($p.Name) (pid $($p.Id))  $($p.Path)"
    if ($_.LocalAddress -notin @('127.0.0.1','::1')) {
        Write-Hit "Bound to $($_.LocalAddress), not loopback — reachable from the network."
    }
}

Write-Host "`nDone.`n" -ForegroundColor Cyan
