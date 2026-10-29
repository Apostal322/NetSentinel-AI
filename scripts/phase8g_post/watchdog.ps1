# Memory watchdog for the Phase 8g post-hoc audit: kills any phase8g python process above 3.4 GB
# (the Phase 8g limit, unchanged) and records the peak working set.
$deadline = (Get-Date).AddMinutes(360); $peak = 0
$root = Join-Path $PSScriptRoot "..\..\reports\phase8g_post"
$log = "$root\watchdog.log"
while ((Get-Date) -lt $deadline) {
  $p = Get-CimInstance Win32_Process -Filter "Name='python.exe'" | Where-Object { $_.CommandLine -like '*phase8g*' }
  foreach ($q in $p) {
    $ws = (Get-Process -Id $q.ProcessId -ErrorAction SilentlyContinue).WorkingSet64
    if ($ws -gt $peak) { $peak = $ws }
    if ($ws -gt 3.4GB) { Stop-Process -Id $q.ProcessId -Force; Add-Content $log "KILLED $($q.CommandLine) at $([math]::Round($ws/1GB,2)) GB" }
  }
  Set-Content "$log.peak" "peak $([math]::Round($peak/1GB,2)) GB at $(Get-Date)"
  if ((Get-Content "$root\run.status" -ErrorAction SilentlyContinue) -match "^done") { break }
  Start-Sleep 5
}
Add-Content $log "watchdog finished $(Get-Date); peak $([math]::Round($peak/1GB,2)) GB"
