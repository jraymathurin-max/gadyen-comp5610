# Gadyen Safeguard - Windows computer self-check (READ-ONLY).
# It changes nothing and reads no client files. It only reads security settings
# and writes gadyen-report.json next to this script.
# Run in PowerShell "as Administrator" for the most complete result:
#   powershell -ExecutionPolicy Bypass -File .\check-windows.ps1

$ErrorActionPreference = "SilentlyContinue"

function Get-DiskEncrypted {
    $vol = Get-BitLockerVolume -MountPoint $env:SystemDrive
    if ($null -eq $vol) { return $null }
    return ($vol.ProtectionStatus -eq "On")
}

function Get-FirewallEnabled {
    $profiles = Get-NetFirewallProfile
    if ($null -eq $profiles) { return $null }
    return -not ($profiles | Where-Object { $_.Enabled -eq $false })
}

function Get-AntivirusEnabled {
    $av = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct
    if ($null -eq $av) { return $null }
    # Bit 12 of productState (0x1000) means "real-time protection on".
    return [bool]($av | Where-Object { ($_.productState -band 0x1000) -ne 0 })
}

function Get-AutoUpdates {
    $svc = Get-Service -Name wuauserv
    if ($null -eq $svc) { return $null }
    $policy = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    if ($policy -and $policy.NoAutoUpdate -eq 1) { return $false }
    return ($svc.StartType -ne "Disabled")
}

function Get-ScreenLockMinutes {
    $active = (Get-ItemProperty "HKCU:\Control Panel\Desktop").ScreenSaveActive
    $secure = (Get-ItemProperty "HKCU:\Control Panel\Desktop").ScreenSaverIsSecure
    $timeout = (Get-ItemProperty "HKCU:\Control Panel\Desktop").ScreenSaveTimeOut
    if ($active -eq "1" -and $secure -eq "1" -and $timeout) { return [int]([int]$timeout / 60) }
    return $null
}

$os = Get-CimInstance Win32_OperatingSystem
$report = [ordered]@{
    schema_version       = 1
    hostname             = $env:COMPUTERNAME
    os                   = "Windows"
    os_version           = "$($os.Caption) $($os.Version)".Substring(0, [Math]::Min(60, "$($os.Caption) $($os.Version)".Length))
    disk_encrypted       = Get-DiskEncrypted
    firewall_enabled     = Get-FirewallEnabled
    antivirus_enabled    = Get-AntivirusEnabled
    auto_updates_enabled = Get-AutoUpdates
    screen_lock_minutes  = Get-ScreenLockMinutes
    collected_at         = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
}
$path = Join-Path $PSScriptRoot "gadyen-report.json"
$report | ConvertTo-Json | Out-File -Encoding utf8 $path
Write-Host "Report written to $path - upload it in Gadyen Safeguard."
