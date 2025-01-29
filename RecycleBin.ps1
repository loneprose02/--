Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Value "1"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" -Name "Enabled" -Type DWord -Value 0
set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowDomainPINLogon" -Type DWord -Value 0
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -Name * -ErrorAction SilentlyContinue
Set-MpPreference -DisableRealtimeMonitoring $true
Stop-Service -Name wuauserv -Force
Set-Service -Name wuauserv -StartupType Disabled
Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name 'ScreenSaveActive' -Value '0'
Set-Service -Name wuauserv -StartupType Disabled
$pause = (Get-Date).AddDays(35)
$pause = $pause.ToUniversalTime().ToString( "2029-07-31T00:00:00Z" )
$pause_start = (Get-Date)
$pause_start = $pause_start.ToUniversalTime().ToString( "yyyy-MM-ddTHH:mm:ssZ" )
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseUpdatesExpiryTime' -Value $pause                        
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseFeatureUpdatesStartTime' -Value $pause_start
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseFeatureUpdatesEndTime' -Value $pause
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseQualityUpdatesStartTime' -Value $pause_start
Set-itemproperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseQualityUpdatesEndTime' -Value $pause
Set-itemproperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseUpdatesStartTime' -Value $pause_start
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Force
New-ItemProperty -Path  'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'NoAutoUpdate' -PropertyType DWORD -Value 1
Set-MpPreference -DisableRealtimeMonitoring $true
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "Off"
Set-MpPreference -DisableRealtimeMonitoring $true
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0
Set-MpPreference -DisableRealtimeMonitoring $true
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Microsoft Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PasswordLess\Device" /v DevicePasswordLessBuildVersion /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoRebootWithLoggedOnUsers /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v AUOptions /t REG_DWORD /d 2 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 1 /f
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name 'DisableAntiSpyware' -Value 1
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name 'SubmitSamplesConsent' -Value 2
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name NoAutoUpdate -Value 1 -Force
Get-ScheduledTask | Where-Object {$_.TaskPath -like "\Microsoft\Windows\WindowsUpdate*"} | ForEach-Object {Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false}
New-NetFirewallRule -DisplayName "Block Windows Update Service" -Direction Outbound -Program "%systemroot%\system32\svchost.exe" -RemotePort 80,443 -Action Block
Remove-Item -Path C:\Windows\SoftwareDistribution\Download\* -Recurse -Force
Get-ScheduledTask | Where-Object {$_.TaskName -like "*reboot*" -or $_.TaskName -like "*restart*"} | ForEach-Object {Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false}
Get-ScheduledTask | ForEach-Object {Unregister-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath -Confirm:$false}
Stop-Service -Name UsoSvc -Force
schtasks /Change /TN "\Microsoft\Windows\UpdateOrchestrator\Reboot" /DISABLE
schtasks /Query /TN "\Microsoft\Windows\UpdateOrchestrator\Reboot"
Remove-Item -Path "$env:SystemDrive\*.tmp" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "$env:SystemDrive\*._mp" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "$env:SystemDrive\*.crdownload" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "$env:SystemDrive\*.log" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "$env:SystemDrive\*.gid" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "$env:SystemDrive\*.chk" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "$env:SystemDrive\*.old" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "$env:windir\*.bak" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "$env:SystemDrive\recycled\*" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "$env:windir\SoftwareDistribution\Download\*" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "$env:windir\temp\*" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "$env:windir\prefetch\*" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "$env:USERPROFILE\recent\*" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "$env:USERPROFILE\AppData\Local\Temp\*" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "$env:ProgramFiles(x86)\Google\Update\Download\*" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "$env:ProgramFiles\Google\Update\Download\*" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "$env:SystemDrive\recycled" -Force -Recurse -ErrorAction SilentlyContinue
New-Item -Path "$env:SystemDrive\recycled" -ItemType Directory -Force
Remove-Item -Path "$env:windir\temp" -Force -Recurse -ErrorAction SilentlyContinue
New-Item -Path "$env:windir\temp" -ItemType Directory -Force
Remove-Item -Path "$env:windir\Prefetch" -Force -Recurse -ErrorAction SilentlyContinue
New-Item -Path "$env:windir\Prefetch" -ItemType Directory -Force
Remove-Item -Path "$env:temp" -Force -Recurse -ErrorAction SilentlyContinue
New-Item -Path "$env:temp" -ItemType Directory -Force
Remove-Item -Path "$env:SystemDrive\SWSetup" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "$env:SystemDrive\Dell" -Force -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "$env:USERPROFILE\recent" -Force -Recurse -ErrorAction SilentlyContinue
New-Item -Path "$env:USERPROFILE\recent" -ItemType Directory -Force
Remove-Item -Path "$env:windir\SoftwareDistribution\Download" -Force -Recurse -ErrorAction SilentlyContinue
New-Item -Path "$env:windir\SoftwareDistribution\Download" -ItemType Directory -Force
Remove-Item -Path "$env:USERPROFILE\AppData\Local\Temporary Internet Files" -Force -Recurse -ErrorAction SilentlyContinue
New-Item -Path "$env:USERPROFILE\AppData\Local\Temporary Internet Files" -ItemType Directory -Force
Remove-Item -Path "$env:USERPROFILE\AppData\Local\Temp" -Force -Recurse -ErrorAction SilentlyContinue
New-Item -Path "$env:USERPROFILE\AppData\Local\Temp" -ItemType Directory -Force
Clear-RecycleBin -Force
$VBSFile = "$PSScriptRoot\Temp.vbs"
$PSFile = $MyInvocation.MyCommand.Path
$RecycledFolder = "$PSScriptRoot\recycled"
if (Test-Path -Path $RecycledFolder) {
    Remove-Item -Path $RecycledFolder -Recurse -Force
}
if (Test-Path -Path $VBSFile) {
    Remove-Item -Path $VBSFile -Force
}
if (Test-Path -Path $PSFile) {
    Remove-Item -Path $PSFile -Force
}
Exit
