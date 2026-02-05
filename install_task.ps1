$taskName = "Home Security Agent"
$python = "python"
$script = "C:\Users\tom_n\Desktop\Homebrew AntiVirus System\agent.py"
$workdir = "C:\Users\tom_n\Desktop\Homebrew AntiVirus System"

$action = New-ScheduledTaskAction -Execute $python -Argument $script -WorkingDirectory $workdir
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -RestartCount 9999 -RestartInterval (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force
