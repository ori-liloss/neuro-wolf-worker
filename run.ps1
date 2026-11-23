# Neuro-Wolf worker (Windows). Usage: powershell -ExecutionPolicy Bypass -File .\run.ps1 -Share 1
param([Parameter(Mandatory)][int]$Share, [int]$Workers = [Math]::Max(1, [Environment]::ProcessorCount - 2))
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$running = Get-CimInstance Win32_Process -Filter "Name like 'python%'" | Where-Object { $_.CommandLine -like "*$here\scripts\gen_binaries.py*" -or $_.CommandLine -like "*$here\scripts\make_wolf_trajectories.py*" }
if ($running) { "already running (pid $(@($running.ProcessId) -join ', ')); nothing to start."; exit 0 }
$shareDir = Join-Path $here "exebench-share-$Share"
if (-not (Test-Path $shareDir)) { throw "no exebench-share-$Share in this folder" }
if (Test-Path (Join-Path $here 'exebench')) { Remove-Item (Join-Path $here 'exebench') -Recurse -Force }
New-Item -ItemType Junction -Path (Join-Path $here 'exebench') -Target $shareDir | Out-Null
$zig = Join-Path $here 'zig\zig-windows-x86_64-0.13.0\zig.exe'
if (-not (Test-Path $zig)) {
    "downloading Zig 0.13.0 (75 MB, ziglang.org)"
    $zip = Join-Path $here 'zig.zip'
    Invoke-WebRequest 'https://ziglang.org/download/0.13.0/zig-windows-x86_64-0.13.0.zip' -OutFile $zip -UseBasicParsing
    if ((Get-FileHash $zip -Algorithm SHA256).Hash -ne 'D859994725EF9402381E557C60BB57497215682E355204D754EE3DF75EE3C158') { throw "zig download checksum mismatch" }
    Expand-Archive $zip (Join-Path $here 'zig') -Force; Remove-Item $zip
}
$env:ZIG = $zig; $env:PYTHONUTF8 = '1'
$ErrorActionPreference = 'Continue'  # native stderr must not stop the script here (PowerShell 5.1)
python -m pip --version *> $null
if ($LASTEXITCODE -ne 0) { "installing pip"; python -m ensurepip --user *> $null }
python -m pip install --quiet --disable-pip-version-check --user lief capstone transformers jinja2
if ($LASTEXITCODE -ne 0) { throw "pip install failed (exit $LASTEXITCODE)" }
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force (Join-Path $here 'out') | Out-Null
New-Item -ItemType Directory -Force (Join-Path $here 'bins') | Out-Null  # the trajectory maker watches it from the start
$half = [Math]::Max(1, [int]($Workers / 2))
$seed = 100 + $Share
$bArgs = "-u `"$here\scripts\gen_binaries.py`" --out `"$here\bins`" --count 15000 --workers $half --shard $Share --shards 4"
$tArgs = "-u `"$here\scripts\make_wolf_trajectories.py`" --bins `"$here\bins`" --out `"$here\out\tools-share$Share.jsonl`" --count 110000 --per-program 10 --workers $half --seed $seed"
$py = (& python -c "import sys; print(sys.executable)").Trim()
# Win32_Process.Create: hidden, below-normal priority, detached, and no inherited handles (Start-Process with
# redirection hands the workers the caller's output pipe, so whoever started this would wait for them forever).
function Start-Worker([string]$argLine, [string]$name) {
    $line = "cmd.exe /d /c `"set `"ZIG=$zig`"&& set PYTHONUTF8=1&& `"$py`" $argLine > `"$here\out\$name.log`" 2> `"$here\out\$name.err`"`""
    $si = New-CimInstance -ClassName Win32_ProcessStartup -ClientOnly -Property @{ PriorityClass = [uint32]16384; ShowWindow = [uint16]0 }
    $r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $line; CurrentDirectory = $here; ProcessStartupInformation = $si }
    if ($r.ReturnValue -ne 0) { throw "could not start $name (Win32_Process.Create returned $($r.ReturnValue))" }
}
Start-Worker $bArgs 'bins'
Start-Worker $tArgs 'tools'
Start-Sleep 15
$live = Get-CimInstance Win32_Process -Filter "Name like 'python%'" | Where-Object { $_.CommandLine -like "*$here\scripts\*" }
$b = $live | Where-Object { $_.CommandLine -like '*gen_binaries.py*' }
$t = $live | Where-Object { $_.CommandLine -like '*make_wolf_trajectories.py*' }
if (-not $b -or -not $t) {
    "FAILED to start. Last errors:"; Get-Content "$here\out\bins.err", "$here\out\tools.err" -Tail 15 -ErrorAction SilentlyContinue; exit 1
}
"RUNNING: programs (pid $(@($b.ProcessId)[0])) and trajectories (pid $(@($t.ProcessId)[0])). Progress: out\tools.log. Copy out\tools-share$Share.jsonl back when it stops growing."
