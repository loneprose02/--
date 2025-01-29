$coinRunPath = "C:\Users\Public\Downloads\xmrig-6.22.2\COINRUN.cmd"

function Start-CoinRun {
  $global:coinRunProcess = Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$coinRunPath`"" -PassThru  # Removed -NoNewWindow
  Write-Host "coinrun.cmd START"
}

Start-CoinRun # Start the process initially

while ($true) {
  if ($global:coinRunProcess.HasExited) {
    Write-Warning "coinrun.cmd STOP. Reboot..."
    Start-CoinRun # Restart the process
  } else {
    Write-Host "coinrun.cmd running..."
  }

  Start-Sleep -Seconds 1800
}
