param([switch]$Capture, [switch]$Restore)
$adb = 'C:\Users\Blanco\AppData\Local\Android\Sdk\platform-tools\adb.exe'
$d = '192.168.1.50:5555'
$state = Join-Path $PSScriptRoot 'tv-state.json'
function Get-Foreground {
    $a = (& $adb -s $d shell 'dumpsys activity activities 2>/dev/null | grep -E "mResumedActivity|topResumedActivity" | head -2' 2>&1) -join "`n"
    $pkg = $null; $act = $null
    if ($a -match '([A-Za-z0-9_.]+)/([A-Za-z0-9_.$]+)') { $pkg = $matches[1]; $act = $matches[2] }
    $inp = (& $adb -s $d shell 'dumpsys tv_input 2>/dev/null | grep -i -m2 "current\|active" ' 2>&1) -join ' '
    [pscustomobject]@{ package = $pkg; activity = $act; tvinput = $inp; captured = (Get-Date).ToString('s') }
}
if ($Capture) {
    $fg = Get-Foreground
    $fg | ConvertTo-Json | Set-Content $state
    "captured: $($fg.package)/$($fg.activity)"
    exit 0
}
if ($Restore) {
    if (-not (Test-Path $state)) { "no saved state"; exit 1 }
    $s = Get-Content $state -Raw | ConvertFrom-Json
    "restoring $($s.package)/$($s.activity)"
    if ($s.package -and $s.activity) {
        (& $adb -s $d shell "am start -n $($s.package)/$($s.activity) 2>&1 | tail -2" 2>&1) -join "`n"
    }
    exit 0
}
# default: capture now
(Get-Foreground) | Format-List
