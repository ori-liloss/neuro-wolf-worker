# Neuro-Wolf worker: one-time setup on a Windows machine.
#   irm https://raw.githubusercontent.com/ori-liloss/neuro-wolf-worker/main/install.ps1 -OutFile $env:TEMP\nw-install.ps1; powershell -ExecutionPolicy Bypass -File $env:TEMP\nw-install.ps1 -Share 1
# Downloads the repo once to %USERPROFILE%\neuro-wolf-worker, starts the work now, and starts it again by itself at
# every logon (a file in the Startup folder, no admin needed). Each start does `git pull` first, never a new clone.
param([Parameter(Mandatory)][ValidateRange(1, 3)][int]$Share)
$ErrorActionPreference = 'Stop'
$dir = Join-Path $env:USERPROFILE 'neuro-wolf-worker'
if (-not (Get-Command git -ErrorAction SilentlyContinue)) { throw 'git is not installed. Install it (winget install Git.Git), open a new window and run this again.' }
if (-not (Get-Command python -ErrorAction SilentlyContinue)) { throw 'python is not on PATH.' }
if (Test-Path (Join-Path $dir '.git')) {
    "already downloaded: $dir (updating)"
    git -C $dir pull --ff-only
} else {
    git clone https://github.com/ori-liloss/neuro-wolf-worker.git $dir
}
$startup = [Environment]::GetFolderPath('Startup')
$cmd = Join-Path $startup 'neuro-wolf-worker.cmd'
Set-Content -Path $cmd -Encoding ascii -Value "@start `"`" /min powershell -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$dir\start.ps1`" -Share $Share"
"autostart at logon: $cmd"
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $dir 'start.ps1') -Share $Share
"installed: share $Share starts at every logon (git pull first). Status of this start is above (RUNNING or FAILED); full log: $dir\out\start.log"
