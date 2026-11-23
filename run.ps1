# Neuro-Wolf worker (Windows). Usage: powershell -ExecutionPolicy Bypass -File .\run.ps1 -Share 1
param([Parameter(Mandatory)][int]$Share, [int]$Workers = [Math]::Max(1, [Environment]::ProcessorCount - 2))
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$share = Join-Path $here "exebench-share-$Share"
if (-not (Test-Path $share)) { throw "no exebench-share-$Share in this folder" }
if (Test-Path (Join-Path $here 'exebench')) { Remove-Item (Join-Path $here 'exebench') -Recurse -Force }
New-Item -ItemType Junction -Path (Join-Path $here 'exebench') -Target $share | Out-Null
$zig = Join-Path $here 'zig\zig-windows-x86_64-0.13.0\zig.exe'
if (-not (Test-Path $zig)) {
    "downloading Zig 0.13.0 (75 MB, ziglang.org)"
    $zip = Join-Path $here 'zig.zip'
    Invoke-WebRequest 'https://ziglang.org/download/0.13.0/zig-windows-x86_64-0.13.0.zip' -OutFile $zip -UseBasicParsing
    if ((Get-FileHash $zip -Algorithm SHA256).Hash -ne 'D859994725EF9402381E557C60BB57497215682E355204D754EE3DF75EE3C158') { throw "zig download checksum mismatch" }
    Expand-Archive $zip (Join-Path $here 'zig') -Force; Remove-Item $zip
}
$env:ZIG = $zig; $env:PYTHONUTF8 = '1'
python -m pip install --quiet lief capstone transformers jinja2
New-Item -ItemType Directory -Force (Join-Path $here 'out') | Out-Null
$b = Start-Process python -ArgumentList '-u', "$here\scripts\gen_binaries.py", '--out', "$here\bins", '--count', '15000', '--workers', [Math]::Max(1, [int]($Workers / 2)), '--shard', $Share, '--shards', '4' -RedirectStandardOutput "$here\out\bins.log" -RedirectStandardError "$here\out\bins.err" -WindowStyle Hidden -PassThru
$b.PriorityClass = 'BelowNormal'
$t = Start-Process python -ArgumentList '-u', "$here\scripts\make_wolf_trajectories.py", '--bins', "$here\bins", '--out', "$here\out\tools-share$Share.jsonl", '--count', '110000', '--per-program', '10', '--workers', [Math]::Max(1, [int]($Workers / 2)), '--seed', (100 + $Share) -RedirectStandardOutput "$here\out\tools.log" -RedirectStandardError "$here\out\tools.err" -WindowStyle Hidden -PassThru
$t.PriorityClass = 'BelowNormal'
"running: programs (pid $($b.Id)) and trajectories (pid $($t.Id)). Progress: out\tools.log. Copy out\tools-share$Share.jsonl back when it stops growing."
