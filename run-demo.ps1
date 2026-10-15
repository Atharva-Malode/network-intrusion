<#
.SYNOPSIS
  One-command launcher for the single-machine NIDS demo.

.DESCRIPTION
  Frees the four demo ports (killing any stale instance) and then opens each
  long-running service in its own PowerShell window, so a re-run never collides
  with a leftover process:
    - backend        FastAPI detector     http://127.0.0.1:8000
    - demo-site      Netflix-clone target http://127.0.0.1:3000
    - capture-proxy  traffic sensor       http://127.0.0.1:8080   <- browse here
    - dashboard      live SOC dashboard   http://127.0.0.1:3001

  Then generate traffic from a 5th window (see the printed hints), e.g.:
    cd attack-script; uv run python main.py demo

  NOTE: use 127.0.0.1, NOT localhost — on Windows "localhost" resolves to IPv6
  (::1) first, and these services bind IPv4, so localhost adds latency / fails.

.PARAMETER Setup
  First-run only: install deps (uv sync / npm install), build the demo site,
  and train the model. Run once, then use the plain launcher afterwards.

.PARAMETER Stop
  Just free the four ports (stop all demo services) and exit — don't relaunch.

.EXAMPLE
  .\run-demo.ps1 -Setup     # first time on this machine
  .\run-demo.ps1            # every run after (auto-frees ports, then starts)
  .\run-demo.ps1 -Stop      # stop everything
#>
param([switch]$Setup, [switch]$Stop)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot

# Demo ports: site 3000, dashboard 3001, backend 8000, proxy 8080.
$PORTS = 8000, 3000, 8080, 3001

# Stop whatever is listening on a TCP port, so the next start binds cleanly.
# This is the fix for "address already in use" crashes after a restart (which
# left the old, buggy instance serving while the new one died).
function Free-Port($port) {
  try {
    $conns = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
  } catch { $conns = $null }
  foreach ($c in $conns) {
    $procId = $c.OwningProcess
    if ($procId -and $procId -gt 4) {
      try {
        Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
        Write-Host "  freed port $port (stopped PID $procId)" -ForegroundColor DarkYellow
      } catch {}
    }
  }
}

function Start-Svc($title, $dir, $cmd) {
  $full = "cd `"$root\$dir`"; Write-Host `"=== $title ===`" -ForegroundColor Cyan; $cmd"
  Start-Process powershell -ArgumentList "-NoExit", "-Command", $full | Out-Null
  Write-Host "  launched: $title" -ForegroundColor Green
}

if ($Setup) {
  Write-Host "First-run setup (deps + build + train). This takes a few minutes..." -ForegroundColor Yellow
  Push-Location "$root\nids-model";              uv sync; uv run python train.py; Pop-Location
  Push-Location "$root\backend";                 uv sync; Pop-Location
  Push-Location "$root\capture-proxy";           uv sync; Pop-Location
  Push-Location "$root\attack-script";           uv sync; Pop-Location
  Push-Location "$root\demo-site\netflix-clone"; npm install; npm run build; Pop-Location
  Push-Location "$root\dashboard";               npm install; Pop-Location
  Write-Host "Setup complete." -ForegroundColor Green
}

Write-Host "`nFreeing demo ports (3000 site, 3001 dashboard, 8000 backend, 8080 proxy)..." -ForegroundColor Yellow
$PORTS | ForEach-Object { Free-Port $_ }
Start-Sleep -Seconds 1

if ($Stop) {
  Write-Host "All demo services stopped." -ForegroundColor Green
  return
}

Write-Host "`nLaunching services (each in its own window)..." -ForegroundColor Yellow
# Backend + site first (the proxy forwards to the site; the dashboard talks to
# the backend), then the proxy and dashboard a moment later.
Start-Svc "backend (:8000)"       "backend"                 "uv run python run.py"
Start-Svc "demo-site (:3000)"     "demo-site\netflix-clone" "npm start -- -p 3000"
Start-Sleep -Seconds 3
Start-Svc "capture-proxy (:8080)" "capture-proxy"           "uv run python proxy.py"
Start-Svc "dashboard (:3001)"     "dashboard"               "npm run dev -- -p 3001"

Write-Host @"

All services launching. Give them ~15s, then:

  1. Dashboard : http://127.0.0.1:3001/monitoring   (top-right should read ONLINE)
  2. Browse    : http://127.0.0.1:8080              (the site, THROUGH the sensor)

  3. Attacks   : open a new window and run one of --
        cd attack-script
        uv run python main.py demo          # scripted tour of all 5 classes
        uv run python main.py recon         # Probe
        uv run python main.py flood         # DoS
        uv run python main.py credential    # R2L
        uv run python main.py exploit       # U2R
        uv run python main.py novel         # NOVEL -> label it on /learning, then Retrain

  (Optional) re-record this machine's live sensor and retrain (~4 min):
        cd attack-script; uv run python main.py calibrate

  Verify detection offline any time:
        cd nids-model; uv run python eval_sensor.py

  To stop everything:  .\run-demo.ps1 -Stop
"@ -ForegroundColor White
