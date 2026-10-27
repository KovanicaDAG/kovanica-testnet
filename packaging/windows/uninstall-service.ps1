# Removes the startup task created by install-service.ps1.
Unregister-ScheduledTask -TaskName "KovanicaLightNode" -Confirm:$false
Write-Output "Removed KovanicaLightNode."
