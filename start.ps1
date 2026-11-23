# Called at logon (and by install.ps1): update the repo, then start the work if it is not already running.
param([Parameter(Mandatory)][int]$Share)
$here = $PSScriptRoot
New-Item -ItemType Directory -Force (Join-Path $here 'out') | Out-Null
$log = Join-Path $here 'out\start.log'
Add-Content $log "$(Get-Date -Format s) start (share $Share)"
try { git -C $here pull --ff-only 2>&1 | Add-Content $log } catch { Add-Content $log "git pull failed: $_ (continuing with what is here)" }
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $here 'run.ps1') -Share $Share 2>&1 | Tee-Object -FilePath $log -Append
