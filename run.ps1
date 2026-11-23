# Neuro-Wolf worker (Windows). Usage: powershell -ExecutionPolicy Bypass -File .\run.ps1 -Share 1
param([Parameter(Mandatory)][int]$Share, [int]$Workers = 0)
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$running = Get-CimInstance Win32_Process -Filter "Name like 'python%'" | Where-Object { $_.CommandLine -like "*$here\scripts\gen_binaries.py*" -or $_.CommandLine -like "*$here\scripts\make_wolf_trajectories.py*" }
# The uploader sends out\tools-share<N>.jsonl to the main PC by itself (scripts\upload.py, wolf_receiver.py there).
function Start-Uploader {
    $up = Get-CimInstance Win32_Process -Filter "Name like 'python%'" | Where-Object { $_.CommandLine -like "*$here\scripts\upload.py*" }
    if ($up) { "uploader already running (pid $(@($up.ProcessId)[0]))"; return }
    New-Item -ItemType Directory -Force (Join-Path $here 'out') | Out-Null
    $pyexe = (& python -c "import sys; print(sys.executable)").Trim()
    $a = "/d /c `"`"$pyexe`" -u `"$here\scripts\upload.py`" --file `"$here\out\tools-share$Share.jsonl`" >> `"$here\out\upload.log`" 2>&1`""
    Start-Process cmd.exe -ArgumentList $a -WorkingDirectory $here -WindowStyle Hidden
    "uploader started: out\tools-share$Share.jsonl goes to the main PC by itself (log: out\upload.log)"
}
if ($running) { "already running (pid $(@($running.ProcessId) -join ', ')); not starting the workers again."; Start-Uploader; exit 0 }
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
if ($Workers -le 0) {
    # Each worker (python + zig, or python + tokenizer) needs about 0.6 GB: never more than the free memory allows.
    $freeGb = (Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1MB
    $Workers = [Math]::Max(2, [Math]::Min([Environment]::ProcessorCount - 2, [int][Math]::Floor($freeGb / 0.6)))
}
"workers: $Workers"
$half = [Math]::Max(1, [int]($Workers / 2))
$seed = 100 + $Share
$bArgs = "-u `"$here\scripts\gen_binaries.py`" --out `"$here\bins`" --count 15000 --workers $half --shard $Share --shards 4 --all-files"
$tArgs = "-u `"$here\scripts\make_wolf_trajectories.py`" --bins `"$here\bins`" --out `"$here\out\tools-share$Share.jsonl`" --count 110000 --per-program 10 --workers $half --seed $seed"
$py = (& python -c "import sys; print(sys.executable)").Trim()
# Start-Process without -Redirect* goes through ShellExecute: hidden, detached, no inherited handles (with
# redirection the workers would inherit the caller's output pipe and whoever started this would wait forever).
# cmd does the redirection. Children of a below-normal process start below normal, so lower this one meanwhile.
function Start-Worker([string]$argLine, [string]$name) {
    $cmdArgs = "/d /c `"`"$py`" $argLine > `"$here\out\$name.log`" 2> `"$here\out\$name.err`"`""
    Start-Process cmd.exe -ArgumentList $cmdArgs -WorkingDirectory $here -WindowStyle Hidden
}
$me = Get-Process -Id $PID; $oldPriority = $me.PriorityClass; $me.PriorityClass = 'BelowNormal'
Start-Worker $bArgs 'bins'
Start-Worker $tArgs 'tools'
$me.PriorityClass = $oldPriority
Start-Sleep 15
$live = Get-CimInstance Win32_Process -Filter "Name like 'python%'" | Where-Object { $_.CommandLine -like "*$here\scripts\*" }
$b = $live | Where-Object { $_.CommandLine -like '*gen_binaries.py*' }
$t = $live | Where-Object { $_.CommandLine -like '*make_wolf_trajectories.py*' }
if (-not $b -or -not $t) {
    "FAILED to start. Last errors:"; Get-Content "$here\out\bins.err", "$here\out\tools.err" -Tail 15 -ErrorAction SilentlyContinue; exit 1
}
Start-Uploader
"RUNNING: programs (pid $(@($b.ProcessId)[0])) and trajectories (pid $(@($t.ProcessId)[0])). Progress: out\tools.log. Copy out\tools-share$Share.jsonl back when it stops growing."
