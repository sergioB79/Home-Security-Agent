$ErrorActionPreference = "Stop"

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$taskName = "Home Security Agent"
$python = "python"
$agent = Join-Path $here "agent.py"
$dashboard = Join-Path $here "dashboard.py"

# Install dependencies
Write-Host "Installing Python dependencies..."
& $python -m pip install -r (Join-Path $here "requirements.txt")

# Register startup task (requires admin)
Write-Host "Registering startup task..."
$action = New-ScheduledTaskAction -Execute $python -Argument $agent -WorkingDirectory $here
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -RestartCount 9999 -RestartInterval (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force

# Desktop shortcut for dashboard
Write-Host "Creating desktop shortcut..."
$desktop = [Environment]::GetFolderPath("Desktop")
$lnk = Join-Path $desktop "Home Security Agent Dashboard.lnk"
$wsh = New-Object -ComObject WScript.Shell
$sc = $wsh.CreateShortcut($lnk)
$sc.TargetPath = $python
$sc.Arguments = "-m streamlit run `"$dashboard`""
$sc.WorkingDirectory = $here
$sc.IconLocation = "$python,0"
$sc.Save()

Write-Host "Done. Use the desktop shortcut to open the dashboard." -ForegroundColor Green
