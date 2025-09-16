<#
  setup-minipc-win11.ps1  — RUN AS ADMIN
  Auto-resume on reboot and optional central log upload.
  Usage:
    - normal run:         powershell -ExecutionPolicy Bypass -File .\setup-minipc-win11.ps1
    - resume run (auto):  powershell -ExecutionPolicy Bypass -File .\setup-minipc-win11.ps1 -Resume
#>

param(
  [switch]$Resume
)

# -------------------- CONFIG --------------------
# Your Drive links (already set from your earlier message)
$GDRIVE_PY_EXE   = "https://drive.google.com/file/d/1PANRP9dGXGla93-BdI3AfmnnDpKNblEG/view?usp=sharing"
$GDRIVE_MEB_ZIP  = "https://drive.google.com/file/d/19qg1MpLobyjUdFDmXnJhhdSJrM8kZ41B/view?usp=sharing"
$GDRIVE_CRD_MSI  = "https://drive.google.com/file/d/1G6IY2CRWAdnTLKcjStJGMQFELX85VEwI/view?usp=sharing"

# If you want the script to copy the log to a network share after provisioning, set this:
# e.g. "\\fileserver\provision-logs"
$CentralLogShare = ""   # <-- set to SMB path if desired, leave empty to skip

# Scheduled task name used for resume
$TaskName = "ProvisionMiniPC_AutoResume"
# ------------------------------------------------

$ErrorActionPreference = 'Stop'

# Paths & logging (define early so functions can use $Log)
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $Here) { $Here = $env:TEMP }   # fallback when run from pipeline
$Log = Join-Path $Here "setup-mini-pc.log"
"=== Run: $(Get-Date) on $env:COMPUTERNAME (Resume=$Resume) ===" | Out-File $Log -Append -Encoding utf8

# -------------------- Guards & helpers --------------------
function WriteLog($m){ $m | Out-File -FilePath $Log -Append -Encoding utf8 }

function Try-Run($scriptBlock, $desc) {
  try { & $scriptBlock; WriteLog "OK: $desc" }
  catch { WriteLog ("ERR: {0} :: {1}" -f $desc, $_.Exception.Message); Write-Warning "Failed: $desc -> $($_.Exception.Message)" }
}

# Admin required
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Error "Please run this script as Administrator."
  exit 1
}

# Small helper to create scheduled task to call this script with -Resume
function Create-ResumeTask {
  param([string]$ScriptPath)
  $escaped = $ScriptPath.Replace('"','\"')
  $action = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$escaped`" -Resume"
  # Use schtasks to create an ONSTART task that runs with highest privileges
  $cmd = "schtasks /Create /RU SYSTEM /RL HIGHEST /SC ONSTART /TN `"$TaskName`" /TR `"$action`" /F"
  WriteLog "Creating resume scheduled task: $cmd"
  cmd.exe /c $cmd | Out-Null
}

function Remove-ResumeTask {
  try { schtasks /Delete /TN $TaskName /F | Out-Null; WriteLog "Removed resume scheduled task $TaskName" } catch { WriteLog "No scheduled task to remove" }
}

# Google Drive downloader (handles large-file confirm flow)
function Download-GoogleDrive {
  param([string]$ShareUrl, [string]$DestinationPath)
  if (-not $ShareUrl) { throw "No URL supplied." }
  # extract id
  if ($ShareUrl -match '/d/([A-Za-z0-9_-]+)') { $id = $Matches[1] }
  elseif ($ShareUrl -match 'id=([A-Za-z0-9_-]+)') { $id = $Matches[1] }
  else { throw "Couldn't parse Google Drive ID from $ShareUrl" }

  $baseUri = "https://docs.google.com/uc?export=download&id=$id"

  # First request
  $handler = New-Object System.Net.Http.HttpClientHandler
  $handler.AllowAutoRedirect = $true
  $client = New-Object System.Net.Http.HttpClient($handler)
  $resp = $client.GetAsync($baseUri).Result
  $ct = $resp.Content.Headers.ContentType.MediaType
  $content = $resp.Content.ReadAsStringAsync().Result

  if ($ct -ne "text/html") {
    [IO.File]::WriteAllBytes($DestinationPath, $resp.Content.ReadAsByteArrayAsync().Result)
    return
  }

  # Look for confirm token in HTML or cookies
  $token = $null
  if ($content -match 'confirm=([0-9A-Za-z_-]+)') { $token = $Matches[1] }
  elseif ($content -match 'name="confirm" value="([0-9A-Za-z_-]+)"') { $token = $Matches[1] }
  else {
    # try cookie-based
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
  } else {
    throw "Drive download failed: $($resp2.StatusCode)"
  }
}

# Get-or-download helper
function Get-Or-Download {
  param([string]$LocalName, [string]$Url)
  $local = Join-Path $Here $LocalName
  if (Test-Path $local) { return $local }
  $dest = Join-Path $env:TEMP $LocalName
  if ($Url -like "*drive.google.com*") {
    WriteLog "Downloading $LocalName from Google Drive..."
    Download-GoogleDrive -ShareUrl $Url -DestinationPath $dest
    return $dest
  } else {
    Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $dest
    return $dest
  }
}

# Defender exclusions (allow provisioning files to not be scanned)
Try-Run {
  Add-MpPreference -ExclusionPath $Here -ErrorAction SilentlyContinue
  Add-MpPreference -ExclusionProcess "powershell.exe" -ErrorAction SilentlyContinue
  Write-Host "Added Defender exclusions for $Here and powershell.exe"
} "Defender exclusions"

# If this is the resume run, remove the scheduled task now so it doesn't loop
if ($Resume) {
  WriteLog "Running as resume after reboot."
  Remove-ResumeTask
}

# Prompt for computer name (if not resume; still allowed on resume)
$DesiredComputerName = Read-Host "Enter computer name (leave blank to keep current: $env:COMPUTERNAME)"
$needReboot = $false

if ($DesiredComputerName -and $DesiredComputerName -ne $env:COMPUTERNAME) {
  Try-Run { Rename-Computer -NewName $DesiredComputerName -Force } "Rename to $DesiredComputerName"
  $needReboot = $true
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

# Set DPI to 125% (LogPixels=120) for current user (needs sign-out/reboot)
Try-Run {
  New-Item -Path "HKCU:\Control Panel\Desktop" -Force | Out-Null
  Set-ItemProperty "HKCU:\Control Panel\Desktop" -Name "LogPixels" -Type DWord -Value 120
  Set-ItemProperty "HKCU:\Control Panel\Desktop" -Name "Win8DpiScaling" -Type DWord -Value 1
  $needReboot = $true
} "Set DPI to 125%"

# Powercfg: no sleep/hybrid/monitor off on AC
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

# Reduce background noise (safe policies) ...
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

# Open CRD UI for interactive activation (you must be signed into Chrome as service@thetrivialcompany.com)
Try-Run { Start-Process "chrome.exe" "https://remotedesktop.google.com/access" } "Open CRD activation page"

# If we need a reboot (rename or DPI change), schedule resume and reboot now (only if not already running as resume)
if (-not $Resume -and $needReboot) {
  # create resume scheduled task that runs ONSTART then reboot
  $scriptPath = $MyInvocation.MyCommand.Path
  Create-ResumeTask -ScriptPath $scriptPath
  Write-Host "Rebooting now to apply changes (script will resume automatically after startup)." -ForegroundColor Yellow
  WriteLog "Scheduled resume task and rebooting."
  Restart-Computer -Force
  exit 0
}

# If running as resume we continue here (or if no reboot needed)
WriteLog "Provisioning main tasks completed."

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

# Clean up resume task if it still exists (safety)
Remove-ResumeTask

Write-Host "`nAll steps attempted. Reboot advised if you changed name/DPI." -ForegroundColor Green
WriteLog "Done: $(Get-Date)"
# OPTIONAL: remove Defender exclusions (left commented intentionally)
# Try-Run { Remove-MpPreference -ExclusionPath $Here -ErrorAction SilentlyContinue; Remove-MpPreference -ExclusionProcess "powershell.exe" -ErrorAction SilentlyContinue } "Cleanup Defender exclusions"
