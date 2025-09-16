<#
  setup-minipc-win11.ps1  — RUN AS ADMIN
  Staged provisioning:
    - Stage A (normal run): rename + set DPI, schedule resume (user logon) and reboot if needed
    - Stage B (resume run): waits for network, downloads (with retries), installs, configures, opens CRD UI
  Usage:
    - normal run:         powershell -ExecutionPolicy Bypass -File .\setup-minipc-win11.ps1
    - resume run (auto):  powershell -ExecutionPolicy Bypass -File .\setup-minipc-win11.ps1 -Resume
#>

param(
  [switch]$Resume
)

# -------------------- CONFIG --------------------
$GDRIVE_PY_EXE   = "https://drive.google.com/file/d/1PANRP9dGXGla93-BdI3AfmnnDpKNblEG/view?usp=sharing"
$GDRIVE_MEB_ZIP  = "https://drive.google.com/file/d/19qg1MpLobyjUdFDmXnJhhdSJrM8kZ41B/view?usp=sharing"
$GDRIVE_CRD_MSI  = "https://drive.google.com/file/d/1G6IY2CRWAdnTLKcjStJGMQFELX85VEwI/view?usp=sharing"

# Optional central log SMB share (set to \\server\share to enable)
$CentralLogShare = ""   # leave empty to skip log upload

# Scheduled task name used for resume
$TaskName = "ProvisionMiniPC_AutoResume"
# ------------------------------------------------

$ErrorActionPreference = 'Stop'

# -------------------- Paths & logging --------------------
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $Here) { $Here = $env:TEMP }   # fallback when run from pipeline
$Log = Join-Path $Here "setup-mini-pc.log"
"=== Run: $(Get-Date) on $env:COMPUTERNAME (Resume=$Resume) ===" | Out-File $Log -Append -Encoding utf8

# -------------------- Helpers --------------------
function WriteLog($m){ $m | Out-File -FilePath $Log -Append -Encoding utf8 }

function Try-Run($scriptBlock, $desc) {
  try { & $scriptBlock; WriteLog "OK: $desc" }
  catch { WriteLog ("ERR: {0} :: {1}" -f $desc, $_.Exception.Message); Write-Warning "Failed: $desc -> $($_.Exception.Message)" }
}

# Scheduled task helpers (try to create as current user on logon; fallback to SYSTEM if that fails)
function Create-ResumeTask {
  param([string]$ScriptPath)
  $escaped = $ScriptPath.Replace('"','\"')
  $action  = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$escaped`" -Resume"

  $user = "$env:USERDOMAIN\$env:USERNAME"
  # try to create ONLOGON task for the current user
  $cmdUser = "schtasks /Create /RU `"$user`" /RL HIGHEST /SC ONLOGON /TN `"$TaskName`" /TR `"$action`" /F"
  WriteLog "Attempting to create resume scheduled task for user $user"
  try {
    cmd.exe /c $cmdUser | Out-Null
    WriteLog "Created resume scheduled task for user $user"
    return
  } catch {
    WriteLog "Failed to create user resume task: $($_.Exception.Message). Trying SYSTEM fallback."
  }

  # fallback: create SYSTEM ONSTART task (works without a password but runs as SYSTEM)
  $cmdSys = "schtasks /Create /RU SYSTEM /RL HIGHEST /SC ONSTART /TN `"$TaskName`" /TR `"$action`" /F"
  try {
    cmd.exe /c $cmdSys | Out-Null
    WriteLog "Created resume scheduled task as SYSTEM (fallback)."
  } catch {
    WriteLog ("Failed to create scheduled task (both user & SYSTEM). Error: {0}" -f $_.Exception.Message)
    throw "Could not create resume scheduled task."
  }
}

function Remove-ResumeTask {
  try { schtasks /Delete /TN $TaskName /F | Out-Null; WriteLog "Removed resume scheduled task $TaskName" } catch { WriteLog "No scheduled task to remove or delete failed." }
}

# Simple network wait (returns $true if DNS resolves)
function Wait-Network {
  param([int]$TimeoutSec = 90)
  $t = [Diagnostics.Stopwatch]::StartNew()
  while ($t.Elapsed.TotalSeconds -lt $TimeoutSec) {
    try {
      [void][System.Net.Dns]::GetHostEntry("www.google.com")
      WriteLog "Network appears ready."
      return $true
    } catch {
      Start-Sleep -Seconds 3
    }
  }
  WriteLog "Network did not become ready within $TimeoutSec seconds."
  return $false
}

# resilient web-request wrapper
function Invoke-WebRequest-Retry {
  param([string]$Uri, [string]$OutFile, [int]$Retries = 3, [int]$DelaySec = 5)
  for ($i=1; $i -le $Retries; $i++) {
    try {
      Invoke-WebRequest -UseBasicParsing -Uri $Uri -OutFile $OutFile -TimeoutSec 120
      WriteLog ("Downloaded {0} -> {1}" -f $Uri, $OutFile)
      return
    } catch {
      WriteLog ("Attempt {0}/{1} failed downloading {2}: {3}" -f $i, $Retries, $Uri, $_.Exception.Message)
      if ($i -eq $Retries) { throw }
      Start-Sleep -Seconds $DelaySec
    }
  }
}

# Google Drive downloader (handles confirm token for large files)
function Download-GoogleDrive {
  param([string]$ShareUrl, [string]$DestinationPath)
  if (-not $ShareUrl) { throw "No URL supplied." }
  if ($ShareUrl -match '/d/([A-Za-z0-9_-]+)') { $id = $Matches[1] }
  elseif ($ShareUrl -match 'id=([A-Za-z0-9_-]+)') { $id = $Matches[1] }
  else { throw "Couldn't parse Google Drive ID from $ShareUrl" }

  $baseUri = "https://docs.google.com/uc?export=download&id=$id"

  $handler = New-Object System.Net.Http.HttpClientHandler
  $handler.AllowAutoRedirect = $true
  $client = New-Object System.Net.Http.HttpClient($handler)
  $resp = $client.GetAsync($baseUri).Result
  $ct = $null
  try { $ct = $resp.Content.Headers.ContentType.MediaType } catch {}
  $content = $resp.Content.ReadAsStringAsync().Result

  if ($ct -and $ct -ne "text/html") {
    [IO.File]::WriteAllBytes($DestinationPath, $resp.Content.ReadAsByteArrayAsync().Result)
    WriteLog "Downloaded drive file (direct) to $DestinationPath"
    return
  }

  # find confirm token in HTML/cookies
  $token = $null
  if ($content -match 'confirm=([0-9A-Za-z_-]+)') { $token = $Matches[1] }
  elseif ($content -match 'name="confirm" value="([0-9A-Za-z_-]+)"') { $token = $Matches[1] }
  else {
    $cookieContainer = New-Object System.Net.CookieContainer
    $handler2 = New-Object System.Net.Http.HttpClientHandler
    $handler2.CookieContainer = $cookieContainer
    $handler2.AllowAutoRedirect = $true
    $client2 = New-Object System.Net.Http.HttpClient($handler2)
    $respTemp = $client2.GetAsync($baseUri).Result
    foreach ($cookie in $cookieContainer.GetCookies([Uri] $baseUri)) {
      if ($cookie.Name -like "download_warning*") { $token = $cookie.Value; break }
    }
  }

  if (-not $token) { throw "Could not obtain Drive confirm token for large file." }

  $uri2 = "$baseUri&confirm=$token"
  $resp2 = $client.GetAsync($uri2).Result
  if ($resp2.IsSuccessStatusCode) {
    [IO.File]::WriteAllBytes($DestinationPath, $resp2.Content.ReadAsByteArrayAsync().Result)
    WriteLog "Downloaded drive file (confirmed) to $DestinationPath"
  } else {
    throw "Drive download failed: $($resp2.StatusCode)"
  }
}

# Get-or-download (local first, then Drive or http(s) with retries)
function Get-Or-Download {
  param([string]$LocalName, [string]$Url)
  $local = Join-Path $Here $LocalName
  if (Test-Path $local) { WriteLog "Found local $local"; return $local }
  $dest = Join-Path $env:TEMP $LocalName

  if ($Url -like "*drive.google.com*") {
    WriteLog "Downloading $LocalName from Google Drive..."
    Download-GoogleDrive -ShareUrl $Url -DestinationPath $dest
    return $dest
  } else {
    Invoke-WebRequest-Retry -Uri $Url -OutFile $dest -Retries 3 -DelaySec 5
    return $dest
  }
}

# Defender exclusions (provisioning folder & PowerShell)
Try-Run {
  Add-MpPreference -ExclusionPath $Here -ErrorAction SilentlyContinue
  Add-MpPreference -ExclusionProcess "powershell.exe" -ErrorAction SilentlyContinue
  Write-Host "Added Defender exclusions for $Here and powershell.exe"
} "Defender exclusions"

# -------------------- Main flow --------------------

# Admin check
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Error "Please run this script as Administrator."
  exit 1
}

# Prompt for computer name (optional)
$DesiredComputerName = Read-Host "Enter computer name (leave blank to keep current: $env:COMPUTERNAME)"
$needReboot = $false

if ($DesiredComputerName -and $DesiredComputerName -ne $env:COMPUTERNAME) {
  Try-Run { Rename-Computer -NewName $DesiredComputerName -Force } "Rename to $DesiredComputerName"
  $needReboot = $true
}

# DPI change (user HKCU) - set and mark reboot
Try-Run {
  New-Item -Path "HKCU:\Control Panel\Desktop" -Force | Out-Null
  Set-ItemProperty "HKCU:\Control Panel\Desktop" -Name "LogPixels" -Type DWord -Value 120
  Set-ItemProperty "HKCU:\Control Panel\Desktop" -Name "Win8DpiScaling" -Type DWord -Value 1
  $needReboot = $true
} "Set DPI to 125%"

# If we need a reboot (rename or DPI), schedule resume and reboot now (only if not already running as resume)
if (-not $Resume -and $needReboot) {
  $scriptPath = $MyInvocation.MyCommand.Path
  Try-Run { Create-ResumeTask -ScriptPath $scriptPath } "Create resume scheduled task"
  Write-Host "Rebooting now to apply rename/DPI changes. Script will resume after logon." -ForegroundColor Yellow
  WriteLog "Scheduled resume task and rebooting."
  Restart-Computer -Force
  exit 0
}

# ---------- Resume phase (or no reboot needed) ----------
if ($Resume) {
  WriteLog "Resume phase started. Waiting for network..."
  if (-not (Wait-Network -TimeoutSec 120)) {
    Write-Warning "Network not ready after wait; continuing anyway (downloads may fail)."
  }

  # Chrome install (skip if present)
  function Test-ChromeInstalled {
    $paths = @("$env:ProgramFiles\Google\Chrome\Application\chrome.exe","$env:ProgramFiles(x86)\Google\Chrome\Application\chrome.exe")
    if ($paths | Where-Object { Test-Path $_ }) { return $true }
    $keys = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall","HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall")
    foreach ($k in $keys) {
      $hit = Get-ChildItem $k -ErrorAction SilentlyContinue | ForEach-Object { try { Get-ItemProperty $_.PSPath } catch { } } | Where-Object { $_.DisplayName -like "Google Chrome*" }
      if ($hit) { return $true }
    }
    return $false
  }
  if (Test-ChromeInstalled) {
    WriteLog "Chrome already present; skipping install."
  } else {
    Try-Run {
      if (Get-Command winget -ErrorAction SilentlyContinue) {
        winget install --id Google.Chrome --silent --accept-source-agreements --accept-package-agreements | Out-Null
      } else { Write-Warning "winget not found; provide Chrome MSI locally." }
    } "Install Chrome"
  }

  # Best-effort set default (interactive on Win11)
  $DefaultAppXml = Join-Path $Here "DefaultAppAssociations.xml"
  if (Test-Path $DefaultAppXml) { Try-Run { Dism /Online /Import-DefaultAppAssociations:$DefaultAppXml | Out-Null } "Import default apps XML" }
  else { Try-Run { Start-Process "ms-settings:defaultapps?apiname=Microsoft.Chrome"; Start-Sleep 12 } "Open Default Apps (interactive)" }

  # Install CRD host
  Try-Run {
    $crdMsiPath = Get-Or-Download -LocalName "chromeremotedesktophost.msi" -Url $GDRIVE_CRD_MSI
    Start-Process msiexec.exe -ArgumentList "/i `"$crdMsiPath`" /qn /norestart" -Wait
  } "Install Chrome Remote Desktop Host"

  # Enable .NET 3.5 (if needed)
  Try-Run { DISM /Online /Enable-Feature /FeatureName:NetFx3 /All /Quiet /NoRestart | Out-Null } ".NET 3.5"

  # Install Python (best-effort)
  Try-Run {
    $pyExe = Get-Or-Download -LocalName "python_installer.exe" -Url $GDRIVE_PY_EXE
    if (Test-Path $pyExe) {
      $ext = [IO.Path]::GetExtension($pyExe).ToLower()
      if ($ext -eq ".msi") {
        Start-Process msiexec.exe -ArgumentList "/i `"$pyExe`" /qn /norestart" -Wait
      } else {
        $installed = $false
        foreach ($sw in @('/quiet InstallAllUsers=1 PrependPath=1','/quiet','/passive','/S','/VERYSILENT','/silent')) {
          try { Start-Process -FilePath $pyExe -ArgumentList $sw -Wait -NoNewWindow -ErrorAction Stop; $installed=$true; break } catch {}
        }
        if (-not $installed) { Write-Warning "Python installer may need interactive run; check installer flags." }
      }
    }
  } "Install Python (best-effort)"

  # Install Machine Expert Basic
  Try-Run {
    $mebZip = Get-Or-Download -LocalName "MachineExpertBasic_V1.2_SP1.zip" -Url $GDRIVE_MEB_ZIP
    $dst = Join-Path $Here "MachineExpertBasic_Extracted"
    if (Test-Path $dst) { Remove-Item $dst -Recurse -Force }
    Expand-Archive -Path $mebZip -DestinationPath $dst -Force
    $msi = Get-ChildItem $dst -Recurse -Filter *.msi -ErrorAction SilentlyContinue | Select-Object -First 1
    $exe = Get-ChildItem $dst -Recurse -Filter *.exe -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'setup|install|machine|expert' } | Select-Object -First 1
    if ($msi) { Start-Process msiexec.exe -ArgumentList "/i `"$($msi.FullName)`" /qn /norestart" -Wait }
    elseif ($exe) {
      $installed = $false
      foreach ($sw in @('/S','/silent','/verysilent','/qn','/s')) {
        try { Start-Process $exe.FullName -ArgumentList $sw -Wait -NoNewWindow; $installed=$true; break } catch {}
      }
      if (-not $installed) { Write-Warning "Machine Expert installer might need interactive run." }
    } else { throw "No installer found inside Machine Expert ZIP." }
  } "Install Machine Expert Basic"

  # Power / background policies
  Try-Run {
    powercfg /HIBERNATE OFF
    powercfg -Change -standby-timeout-ac 0
    powercfg -Change -monitor-timeout-ac 0
    powercfg -Change -disk-timeout-ac 0
    powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_VIDEO ADAPTBRIGHT 0
    powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_SLEEP HYBRIDSLEEP 0
    powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_SLEEP STANDBYIDLE 0
    powercfg -SetActive SCHEME_CURRENT
  } "Keep system awake"

  Try-Run {
    New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
    Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Type DWord -Value 1
    Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Type DWord -Value 2
    New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
    Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1
    New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Force | Out-Null
    Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "DisableSearchBoxSuggestions" -Type DWord -Value 1
    New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" -Force | Out-Null
    Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" -Name "AllowNewsAndInterests" -Type DWord -Value 0
    New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
    Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsRunInBackground" -Type DWord -Value 2
    Try { Stop-Service WSearch -Force } Catch {}
    Set-Service WSearch -StartupType Disabled
    New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Force | Out-Null
    Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSync" -Type DWord -Value 1
  } "Reduce background activity"

  # Firewall for CRD if present
  Try-Run {
    $hostExe = "$env:ProgramFiles\Google\Chrome Remote Desktop\CurrentVersion\remoting_host.exe"
    if (Test-Path $hostExe) {
      New-NetFirewallRule -DisplayName "Chrome Remote Desktop Inbound" -Direction Inbound -Program $hostExe -Action Allow -Protocol TCP -Profile Any -ErrorAction SilentlyContinue | Out-Null
      New-NetFirewallRule -DisplayName "Chrome Remote Desktop Outbound" -Direction Outbound -Program $hostExe -Action Allow -Protocol TCP -Profile Any -ErrorAction SilentlyContinue | Out-Null
    }
  } "Firewall rules for CRD"

  # Launch CRD UI for interactive activation (you must sign into Chrome as service@thetrivialcompany.com)
  Try-Run { Start-Process "chrome.exe" "https://remotedesktop.google.com/access" } "Open CRD activation page"

  # Optional: upload log to central SMB share (if configured)
  if ($CentralLogShare -and ($CentralLogShare -ne "")) {
    try {
      $host = (Get-WmiObject Win32_ComputerSystem).Name
      $dstDir = Join-Path $CentralLogShare $host
      if (-not (Test-Path $dstDir)) { New-Item -Path $dstDir -ItemType Directory -Force | Out-Null }
      $destFile = Join-Path $dstDir ("setup-mini-pc_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".log")
      Copy-Item -Path $Log -Destination $destFile -Force
      WriteLog ("Uploaded log to {0}" -f $dstDir)
    } catch {
      WriteLog ("Failed to upload log to {0}: {1}" -f $CentralLogShare, $_.Exception.Message)
    }
  }

  # Clean up resume task if it still exists
  Remove-ResumeTask

  WriteLog "Resume-phase: completed main tasks."
  Write-Host "`nAll resume-phase steps attempted. Reboot if necessary." -ForegroundColor Green
}

if (-not $Resume -and -not $needReboot) {
  WriteLog "No reboot requested and running in immediate mode; invoking resume-phase tasks inline."
  $scriptPath = $PSCommandPath
  if (-not $scriptPath) { $scriptPath = $MyInvocation.MyCommand.Path }
  if ($scriptPath) {
    & $scriptPath -Resume
  } else {
    Write-Warning "Could not determine script path for inline resume run."
  }
}


# Finalize
WriteLog "Done: $(Get-Date)"
