# WinPersist Hunter -- canary teardown
# Removes everything setup.ps1 planted. Safe to run multiple times.

$ErrorActionPreference = 'SilentlyContinue'

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

$IsAdmin = Test-Admin
Write-Host "WinPersist Hunter -- canary teardown" -ForegroundColor Green

# ---------- HKCU ----------------------------------------------------------

Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' `
    -Name 'WPH_CANARY_RunEnc' -ErrorAction SilentlyContinue
Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce' `
    -Name 'WPH_CANARY_PublicDownload' -ErrorAction SilentlyContinue

# Restore screensaver to empty
try {
    Remove-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name 'SCRNSAVE.EXE' -ErrorAction Stop
} catch {
    Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name 'SCRNSAVE.EXE' -Value ''
}

$startVbs = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup\WPH_CANARY_start.vbs'
if (Test-Path $startVbs) { Remove-Item $startVbs -Force }

# COM hijack
Remove-Item -Path 'HKCU:\Software\Classes\CLSID\{13709620-C279-11CE-A49E-444553540000}' `
    -Recurse -Force -ErrorAction SilentlyContinue

# ---------- HKLM / admin -------------------------------------------------

if ($IsAdmin) {
    Remove-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\WPH_CANARY_target.exe' `
        -Recurse -Force -ErrorAction SilentlyContinue

    Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' `
        -Name 'UserinitMprLogonScript' -ErrorAction SilentlyContinue

    Remove-Item -Path 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{D7F5C7B0-FFFF-CA17-0000-WPHCANARY00}' `
        -Recurse -Force -ErrorAction SilentlyContinue

    Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Netsh' `
        -Name 'WPH_CANARY_helper' -ErrorAction SilentlyContinue

    Remove-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\WPH_CANARY_provider' `
        -Recurse -Force -ErrorAction SilentlyContinue

    Remove-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors\WPH_CANARY_monitor' `
        -Recurse -Force -ErrorAction SilentlyContinue

    Remove-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB\{ABCD0000-WPHC-ANAR-Y000-000000000000}' `
        -Recurse -Force -ErrorAction SilentlyContinue

    # Restore SetupExecute to empty MULTI_SZ
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' `
        -Name 'SetupExecute' -Value @() -Type MultiString -ErrorAction SilentlyContinue

    # Empty AppCertDLLs back out
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' `
        -Name 'AppCertDLLs' -Value @() -Type MultiString -ErrorAction SilentlyContinue

    schtasks /Delete /TN "WPH_CANARY_Task" /F 2>$null | Out-Null

    # BITS
    try {
        Import-Module BitsTransfer -ErrorAction Stop
        Get-BitsTransfer -AllUsers | Where-Object { $_.DisplayName -eq 'WPH_CANARY_BITS' } |
            Remove-BitsTransfer
    } catch {}

    # WMI
    Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding |
        Where-Object { $_.Consumer -match 'WPH_CANARY_Consumer' -or $_.Filter -match 'WPH_CANARY_Filter' } |
        ForEach-Object { $_.Delete() }
    Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer |
        Where-Object { $_.Name -eq 'WPH_CANARY_Consumer' } |
        ForEach-Object { $_.Delete() }
    Get-WmiObject -Namespace root\subscription -Class __EventFilter |
        Where-Object { $_.Name -eq 'WPH_CANARY_Filter' } |
        ForEach-Object { $_.Delete() }
} else {
    Write-Host "[i] Not admin -- skipping HKLM / service / WMI cleanup." -ForegroundColor Yellow
}

Write-Host "Done." -ForegroundColor Green
