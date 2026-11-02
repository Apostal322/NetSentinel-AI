# Memory watchdog for the Phase 8i runs: kills any phase8i (or NetFlow ingest) python process above 3.4 GB
# (the project limit, unchanged) and records the peak working set.
# It reads each process's PEAK working set (kept by the OS), so an overrun shorter than the 5 s poll is
# still detected and logged (Phase 8i audit; before, two brief overruns went unseen). Detection can lag by
# up to 5 s; hard prevention is scripts/run_capped.py (OS-enforced cap).
$deadline = (Get-Date).AddMinutes(360); $peak = 0
$root = Join-Path $PSScriptRoot "..\..\reports\phase8i"
$log = "$root\watchdog.log"
while ((Get-Date) -lt $deadline) {
  $p = Get-CimInstance Win32_Process -Filter "Name='python.exe'" | Where-Object { ($_.CommandLine -like '*phase8i*' -or $_.CommandLine -like '*ingest-nf*') }
  foreach ($q in $p) {
    $ws = (Get-Process -Id $q.ProcessId -ErrorAction SilentlyContinue).PeakWorkingSet64
    if ($ws -gt $peak) { $peak = $ws }
    if ($ws -gt 3.4GB) { Stop-Process -Id $q.ProcessId -Force; Add-Content $log "KILLED $($q.CommandLine): peak $([math]::Round($ws/1GB,2)) GB" }
  }
  Set-Content "$log.peak" "peak $([math]::Round($peak/1GB,2)) GB at $(Get-Date)"
  if ((Get-Content "$root\run.status" -ErrorAction SilentlyContinue) -match "^done") { break }
  Start-Sleep 5
}
Add-Content $log "watchdog finished $(Get-Date); peak $([math]::Round($peak/1GB,2)) GB"
