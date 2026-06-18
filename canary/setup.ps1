# WinPersist Hunter -- canary setup
#
# Plants a collection of harmless persistence "canaries" so each hunting
# module has something to detect. Every entry uses the WPH_CANARY_ prefix or
# is otherwise tagged, so teardown.ps1 can reliably remove them.
#
# Canaries point at calc.exe, notepad.exe, or a non-existent path --
# they don't actually run malicious code, and many are deliberately
# unreachable (HKCU keys, fake DLL names) so they never fire on logon
# even if you forget to tear them down.
#
# Usage:
#   PS> .\canary\setup.ps1                 # plants HKCU-only canaries
#   PS> .\canary\setup.ps1                 # (admin) also HKLM, service, WMI
#   PS> python winpersist.py               # see the detections
#   PS> .\canary\teardown.ps1              # remove canaries
#
# This script is READ-AWARE: it never overwrites an existing value with that
# exact name (it always uses WPH_CANARY_* names), so you can run it twice
# safely.

$ErrorActionPreference = 'Continue'

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

$IsAdmin  = Test-Admin
$Canaries = @()

function Plant {
    param([string]$Module, [string]$Description, [scriptblock]$Action)
    Write-Host "[+] $Module -- $Description" -ForegroundColor Cyan
    try {
        & $Action
        $script:Canaries += "$Module"
    } catch {
        Write-Host "    ! failed: $_" -ForegroundColor Yellow
    }
}

Write-Host "WinPersist Hunter -- canary setup" -ForegroundColor Green
Write-Host ("Admin: {0}" -f $IsAdmin) -ForegroundColor Green
Write-Host ""

# ---------------- HKCU-only canaries (no admin needed) ---------------------

Plant "run_keys" "HKCU Run value with obfuscated PowerShell" {
    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
        -Force | Out-Null
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
        -Name "WPH_CANARY_RunEnc" `
        -Value 'powershell.exe -nop -w hidden -enc SQBFAFgAIAAoACgAJABjAGEAbgBhAHIAeQApACkA'
}

Plant "run_keys" "HKCU RunOnce pointing to Public Downloads" {
    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce" `
        -Force | Out-Null
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce" `
        -Name "WPH_CANARY_PublicDownload" `
        -Value 'C:\Users\Public\Downloads\WPH_canary_payload.exe'
}

Plant "startup_folders" "Startup folder .vbs canary" {
    $f = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup\WPH_CANARY_start.vbs'
    Set-Content -LiteralPath $f -Value "' WPH canary -- does nothing" -Encoding ASCII
}

Plant "screensaver" "User screensaver redirected to AppData" {
    Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' `
        -Name 'SCRNSAVE.EXE' `
        -Value "$env:LOCALAPPDATA\WPH_CANARY_scr.scr"
}

Plant "com_hijack" "HKCU CLSID shadowing Shell.Application (HKLM)" {
    $clsid = '{13709620-C279-11CE-A49E-444553540000}'  # Shell.Application
    $p = "HKCU:\Software\Classes\CLSID\$clsid\InprocServer32"
    New-Item -Path $p -Force | Out-Null
    Set-ItemProperty -Path $p -Name '(default)' `
        -Value "$env:APPDATA\WPH_CANARY_hijack.dll"
}

Plant "office_persistence" "Recently touched Normal.dotm marker (no overwrite)" {
    $normal = Join-Path $env:APPDATA 'Microsoft\Templates\Normal.dotm'
    if (Test-Path $normal) {
        Write-Host "    (skipping -- Normal.dotm already exists, won't touch)" -ForegroundColor DarkGray
    } else {
        Write-Host "    (skipping -- Word not installed, nothing to canary)" -ForegroundColor DarkGray
    }
}

Plant "browser_extensions" "Note: no browser-extension canary (would require profile edit)" {
    Write-Host "    (skipped -- not safe to script a real Preferences edit)" -ForegroundColor DarkGray
}

# ---------------- Admin-only canaries -------------------------------------

if (-not $IsAdmin) {
    Write-Host ""
    Write-Host "[i] Skipping HKLM/service/WMI canaries -- not running as admin." `
        -ForegroundColor Yellow
} else {
    Plant "ifeo" "IFEO Debugger on calc.exe (sticky-keys-style)" {
        $p = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\WPH_CANARY_target.exe'
        New-Item -Path $p -Force | Out-Null
        Set-ItemProperty -Path $p -Name 'Debugger' `
            -Value 'C:\Windows\System32\calc.exe'
    }

    Plant "winlogon" "Winlogon UserinitMprLogonScript canary" {
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' `
            -Name 'UserinitMprLogonScript' `
            -Value "$env:PROGRAMDATA\WPH_CANARY_logon.bat" -Force
    }

    Plant "active_setup" "Active Setup component with calc.exe StubPath" {
        $g = '{D7F5C7B0-FFFF-CA17-0000-WPHCANARY00}'
        $p = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\$g"
        New-Item -Path $p -Force | Out-Null
        Set-ItemProperty -Path $p -Name '(default)' -Value 'WPH Canary Component'
        Set-ItemProperty -Path $p -Name 'StubPath' `
            -Value "$env:APPDATA\WPH_CANARY_active.exe /install"
    }

    Plant "netsh_helper" "Non-default netsh helper DLL" {
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Netsh' `
            -Name 'WPH_CANARY_helper' `
            -Value 'WPH_CANARY_helper.dll' -Force
    }

    Plant "time_providers" "Fake W32Time provider" {
        $p = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\WPH_CANARY_provider'
        New-Item -Path $p -Force | Out-Null
        Set-ItemProperty -Path $p -Name 'DllName' `
            -Value "$env:PROGRAMDATA\WPH_CANARY_tp.dll"
        Set-ItemProperty -Path $p -Name 'Enabled' -Value 0 -Type DWord
    }

    Plant "print_monitors" "Fake print monitor DLL" {
        $p = 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors\WPH_CANARY_monitor'
        New-Item -Path $p -Force | Out-Null
        Set-ItemProperty -Path $p -Name 'Driver' -Value 'WPH_CANARY_mon.dll'
    }

    Plant "shim_database" "Custom shim entry under InstalledSDB" {
        $g = '{ABCD0000-WPHC-ANAR-Y000-000000000000}'
        $p = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB\$g"
        New-Item -Path $p -Force | Out-Null
        Set-ItemProperty -Path $p -Name 'DatabaseDescription' `
            -Value 'WPH Canary Shim'
        Set-ItemProperty -Path $p -Name 'DatabasePath' `
            -Value "$env:PROGRAMDATA\WPH_CANARY_shim.sdb"
    }

    Plant "boot_execute" "Non-default Session Manager SetupExecute" {
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' `
            -Name 'SetupExecute' `
            -Value @('WPH_CANARY_setup_exec') -Type MultiString
    }

    Plant "appinit_lsa" "AppCertDLLs canary (Wow64 too if present)" {
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' `
            -Name 'AppCertDLLs' `
            -Value @("$env:PROGRAMDATA\WPH_CANARY_appcert.dll") -Type MultiString -Force
    }

    Plant "scheduled_tasks" "Hidden non-Microsoft scheduled task running mshta" {
        $xml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>WPH Canary</Author>
    <Description>WPH canary -- harmless</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger><Enabled>true</Enabled></LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <Hidden>true</Hidden>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>mshta.exe</Command>
      <Arguments>javascript:close()</Arguments>
    </Exec>
  </Actions>
</Task>
"@
        $tmp = New-TemporaryFile
        Set-Content -LiteralPath $tmp -Value $xml -Encoding Unicode
        # /XML route, never enabled until /RU is given; we use SYSTEM but
        # the task is harmless (mshta of javascript:close()).
        schtasks /Create /TN "WPH_CANARY_Task" /XML "$tmp" /F | Out-Null
        Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue
    }

    Plant "bits_jobs" "BITS job with NotifyCmdLine" {
        try {
            Import-Module BitsTransfer -ErrorAction Stop
            $job = Start-BitsTransfer -Suspended `
                -Source 'http://127.0.0.1/wph_canary' `
                -Destination "$env:TEMP\WPH_CANARY_bits.tmp" `
                -DisplayName 'WPH_CANARY_BITS' -Asynchronous
            # Set NotifyCmdLine -- this is what makes the module fire
            $job | Set-BitsTransfer -NotifyCmdLine `
                @('cmd.exe','/c','echo WPH canary')
        } catch {
            Write-Host "    (skipped -- BITS unavailable)" -ForegroundColor DarkGray
        }
    }

    Plant "wmi_subs" "WMI CommandLineEventConsumer canary" {
        try {
            $f = Set-WmiInstance -Namespace root\subscription -Class __EventFilter `
                -Arguments @{
                    Name='WPH_CANARY_Filter'; EventNamespace='root\cimv2';
                    QueryLanguage='WQL';
                    Query="SELECT * FROM __InstanceCreationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime'"
                }
            $c = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer `
                -Arguments @{
                    Name='WPH_CANARY_Consumer';
                    CommandLineTemplate='cmd.exe /c echo WPH canary'
                }
            Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding `
                -Arguments @{ Filter=$f; Consumer=$c } | Out-Null
        } catch {
            Write-Host "    (skipped -- WMI subscription failed: $_)" -ForegroundColor DarkGray
        }
    }
}

Write-Host ""
Write-Host ("Planted {0} canary group(s)." -f $Canaries.Count) -ForegroundColor Green
Write-Host "Now run:  python winpersist.py --offline-feed" -ForegroundColor Green
Write-Host "Clean up: .\canary\teardown.ps1"               -ForegroundColor Green
