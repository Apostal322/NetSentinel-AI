# Memory watchdog for Phase 8g analyses: kills any phase8g python process above 3.4 GB.
$deadline = (Get-Date).AddMinutes(120); $peak = 0
$log = "C:\Users\marke\projects\netsentinel-ai\reports\phase8g\watchdog.log"
while ((Get-Date) -lt $deadline) {
  $p = Get-CimInstance Win32_Process -Filter "Name='python.exe'" | Where-Object { $_.CommandLine -like '*phase8g*' }
  foreach ($q in $p) {
    $ws = (Get-Process -Id $q.ProcessId -ErrorAction SilentlyContinue).WorkingSet64
    if ($ws -gt $peak) { $peak = $ws }
    if ($ws -gt 3.4GB) { Stop-Process -Id $q.ProcessId -Force; Add-Content $log "KILLED $($q.CommandLine) at $([math]::Round($ws/1GB,2)) GB" }
  }
  Set-Content "$log.peak" "peak $([math]::Round($peak/1GB,2)) GB at $(Get-Date)"
  if ((Get-Content "C:\Users\marke\projects\netsentinel-ai\reports\phase8g\run.status" -ErrorAction SilentlyContinue) -match "^done") { break }
  Start-Sleep 5
}
Add-Content $log "watchdog finished; peak $([math]::Round($peak/1GB,2)) GB"
