# Registers the Kovanica light node to start at boot. There is no tray icon.
# The executable stays in the foreground; Windows Task Scheduler is the wrapper
# because the binary does not speak the Service Control Manager protocol.
#
# Usage (Administrator PowerShell):
#   .\install-service.ps1 -Exe C:\kovanica\kovanica-lightnode.exe
#
# Put the passphrase in the machine environment as KOVANICA_LIGHT_PASSPHRASE
# before the task starts. The task runs as SYSTEM and inherits machine variables.

param(
    [Parameter(Mandatory = $true)]
    [string]$Exe,
    [string]$DataDir = "C:\ProgramData\kovanica-lightnode"
)

$ErrorActionPreference = "Stop"
$resolved = (Resolve-Path $Exe).Path
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null

$action = New-ScheduledTaskAction -Execute $resolved -Argument "--data-dir `"$DataDir`" run"
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)
Register-ScheduledTask -TaskName "KovanicaLightNode" -Action $action -Trigger $trigger -Settings $settings -User "SYSTEM" -RunLevel Highest -Force | Out-Null
Write-Output "Registered KovanicaLightNode. It runs `"$resolved --data-dir $DataDir run`" at startup."
Write-Output "Set machine environment KOVANICA_LIGHT_PASSPHRASE so the witness can be signed. No tray is installed."
