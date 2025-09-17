<#
  setup-minipc-win11.ps1  — RUN AS ADMIN (PowerShell 5.1 compatible)

  Stage A: optional rename + set DPI → schedule resume & reboot if needed
  Stage B: installs/config with retries & fallbacks, Chrome sign-in, CRD, keep-awake, light hardening
  Manual fallback: if a download fails, Chrome opens your Drive link(s) or vendor page and the script waits for you.
#>

param([switch]$Resume)

# -------------------- YOUR DRIVE LINKS --------------------
$GDRIVE_PY_EXE      = "https://drive.google.com/file/d/1PANRP9dGXGla93-BdI3AfmnnDpKNblEG/view?usp=sharing"
$GDRIVE_MEB_EXE     = "https://drive.google.com/file/d/1CfLdcXN1DqRZDGCWsPxpo3XFS7kbmMrN/view?usp=sharing"
$GDRIVE_CRD_MSI     = "https://drive.google.com/file/d/1G6IY2CRWAdnTLKcjStJGMQFELX85VEwI/view?usp=sharing"
$GDRIVE_FOLDER_ROOT = "https://drive.google.com/drive/folders/1FuLqB892C_6ktjGnyV-X4qPQqeDr0-D8?usp=drive_link"

# -------------------- PUBLIC FALLBACKS --------------------
$FALLBACK_CHROME_MSI = "https://dl.google.com/chrome/install/GoogleChromeStandaloneEnterprise64.msi"
$FALLBACK_CRD_MSI    = "https://dl.google.com/edgedl/chrome-remote-desktop/chromeremotedesktophost.msi"  # <- fixed
$FALLBACK_PY_EXE     = "https://www.python.org/ftp/python/3.12.6/python-3.12.6-amd64.exe"

# Optional central SMB log share (e.g., "\\server\provision-logs"); leave empty to skip
$CentralLogShare = ""

$TaskName = "ProvisionMiniPC_AutoResume"
$ErrorActionPreference = 'Stop'

# Force TLS 1.2 for Invoke-WebRequest on fresh images
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# -------------------- Paths & logging --------------------
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $Here) { $Here = $env:TEMP }
$Log  = Join-Path $Here "setup-mini-pc.log"
"=== Run: $(Get-Date) on $env:COMPUTERNAME (Resume=$Resume) ===" | Out-File $Log -Append -Encoding utf8

function WriteLog($m){ $m | Out-File -FilePath $Log -Append -Encoding utf8 }
function Try-Run($sb, $desc){ try{ & $sb; WriteLog "OK: $desc" } catch{ WriteLog ("ERR: {0} :: {1}" -f $desc, $_.Exception.Message); Write-Warning "Failed: $desc -> $($_.Exception.Message)" } }

# -------------------- Admin check --------------------
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Write-Error "Run this script as Administrator."; exit 1 }

# -------------------- Helpers (PS5.1-friendly) --------------------
function Wait-Network([int]$TimeoutSec=120){
  $sw=[Diagnostics.Stopwatch]::StartNew()
  while($sw.Elapsed.TotalSeconds -lt $TimeoutSec){
    try{ [void][System.Net.Dns]::GetHostEntry("www.google.com"); WriteLog "Network ready"; return $true }
    catch{ Start-Sleep 3 }
  }
  WriteLog "Network NOT ready after $TimeoutSec s"; return $false
}

function Invoke-WebRequest-Retry([string]$Uri,[string]$OutFile,[int]$Retries=4,[int]$DelaySec=8,[int]$TimeoutSec=1800){
  for($i=1;$i -le $Retries;$i++){
    try{
      if(Test-Path $OutFile){ Remove-Item $OutFile -Force -ErrorAction SilentlyContinue }
      Invoke-WebRequest -UseBasicParsing -Uri $Uri -OutFile $OutFile -TimeoutSec $TimeoutSec
      if((Test-Path $OutFile) -and ((Get-Item $OutFile).Length -gt 1MB)){ return }
      throw "Downloaded file missing or too small"
    }catch{
      WriteLog ("Attempt {0}/{1} failed: {2}" -f $i,$Retries,$_.Exception.Message)
      if($i -eq $Retries){ throw }
      Start-Sleep $DelaySec
    }
  }
}

# --- Validation helpers ---
function Test-InstallerMagic {
  param([string]$Path)
  if (-not (Test-Path $Path)) { return $false }
  try {
    $fs = [System.IO.File]::Open($Path, 'Open', 'Read', 'Read')
    $br = New-Object System.IO.BinaryReader($fs)
    $bytes = $br.ReadBytes(8)
    $br.Dispose(); $fs.Dispose()
    if ($bytes.Length -lt 2) { return $false }
    if ($bytes[0] -eq 0x4D -and $bytes[1] -eq 0x5A) { return $true } # EXE MZ
    if ($bytes.Length -ge 8 -and $bytes[0] -eq 0xD0 -and $bytes[1] -eq 0xCF -and $bytes[2] -eq 0x11 -and $bytes[3] -eq 0xE0 -and $bytes[4] -eq 0xA1 -and $bytes[5] -eq 0xB1 -and $bytes[6] -eq 0x1A -and $bytes[7] -eq 0xE1){ return $true } # MSI OLE
  } catch { }
  return $false
}

function Test-NotHtml {
  param([string]$Path)
  if (-not (Test-Path $Path)) { return $false }
  try {
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 32) { return $false }
    $sliceLen = [Math]::Min(2048, $bytes.Length)
    $text = [System.Text.Encoding]::ASCII.GetString($bytes, 0, $sliceLen)
    if ($text -match '<\!DOCTYPE\s+html' -or $text -match '<html' -or $text -match 'Google Drive' -or $text -match 'quota exceeded' -or $text -match 'Sign in') { return $false }
    return $true
  } catch { return $false }
}

# Google Drive downloader (confirm-token + content validation)
function Download-GoogleDrive {
  param(
    [string]$ShareUrl,
    [string]$DestinationPath,
    [int]$TimeoutSec = 3600,
    [int]$MinBytes   = 1MB
  )
  if (-not $ShareUrl) { throw "No URL supplied." }

  $id = $null
  if ($ShareUrl -match '/d/([A-Za-z0-9_-]+)') { $id = $Matches[1] }
  elseif ($ShareUrl -match 'id=([A-Za-z0-9_-]+)') { $id = $Matches[1] }
  if (-not $id) { throw "Couldn't parse Google Drive ID from $ShareUrl" }

  $base = "https://docs.google.com/uc?export=download&id=$id"
  if (Test-Path $DestinationPath) { Remove-Item $DestinationPath -Force -ErrorAction SilentlyContinue }

  $sess = $null
  $headers = @{
    'User-Agent' = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36'
    'Accept'     = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
  }

  $r1 = Invoke-WebRequest -UseBasicParsing -Uri $base -Headers $headers -SessionVariable sess -TimeoutSec $TimeoutSec

  if ($r1.Headers['Content-Type'] -and $r1.Headers['Content-Type'] -notlike 'text/html*') {
    Invoke-WebRequest -UseBasicParsing -Uri $base -WebSession $sess -OutFile $DestinationPath -Headers $headers -TimeoutSec $TimeoutSec
  } else {
    $token = $null
    foreach ($cookie in $sess.Cookies.GetCookies([Uri]$base)) { if ($cookie.Name -like 'download_warning*') { $token = $cookie.Value; break } }
    if (-not $token) {
      $html = $r1.Content
      if     ($html -match 'confirm=([0-9A-Za-z_-]+)')                   { $token = $Matches[1] }
      elseif ($html -match 'name="confirm"\s+value="([0-9A-Za-z_-]+)"')  { $token = $Matches[1] }
      elseif ($html -match 'href="[^"]*?confirm=([0-9A-Za-z_-]+)[^"]*"') { $token = $Matches[1] }
    }
    if (-not $token) { throw "Could not obtain Drive confirm token (large file flow or permissions not public)." }
    $dlUrl = "$base&confirm=$token"
    Invoke-WebRequest -UseBasicParsing -Uri $dlUrl -WebSession $sess -OutFile $DestinationPath -Headers $headers -TimeoutSec $TimeoutSec
  }

  if (-not (Test-Path $DestinationPath)) { throw "Download failed (no file)." }
  $len = (Get-Item $DestinationPath).Length
  if ($len -lt $MinBytes) { throw "Download too small ($len bytes) - likely an error page." }
  if (-not (Test-NotHtml -Path $DestinationPath)) { throw "Downloaded HTML/error page instead of the binary (check sharing/quota)." }
  if (-not (Test-InstallerMagic -Path $DestinationPath)) { throw "Downloaded file is not a valid EXE/MSI (magic bytes mismatch)." }

  $stableCount=0; $lastSize=-1
  while($stableCount -lt 3){
    if(-not (Test-Path $DestinationPath)){ Start-Sleep 2; continue }
    $sz=(Get-Item $DestinationPath).Length
    if($sz -eq $lastSize -and $sz -ge $MinBytes){ $stableCount++ } else { $stableCount=0; $lastSize=$sz }
    Start-Sleep 2
  }
}

# Download chain with multiple fallbacks + validation
function Get-FromSources {
  param(
    [string]$LocalName,
    [string[]]$Sources,
    [int]$MinBytes = 1MB
  )
  $local = Join-Path $Here $LocalName
  if (Test-Path $local -and (Get-Item $local).Length -ge $MinBytes -and (Test-NotHtml $local) -and (Test-InstallerMagic $local)) {
    WriteLog "Using local $local"; return $local
  }

  $dest = Join-Path $env:TEMP $LocalName
  foreach ($u in $Sources) {
    if (-not $u) { continue }
    try {
      if (Test-Path $dest) { Remove-Item $dest -Force -ErrorAction SilentlyContinue }
      if ($u -like "*drive.google.com*") {
        WriteLog "Downloading from Drive: $u"
        Download-GoogleDrive -ShareUrl $u -DestinationPath $dest -TimeoutSec 3600 -MinBytes $MinBytes
      } else {
        WriteLog "Downloading: $u"
        Invoke-WebRequest-Retry -Uri $u -OutFile $dest -Retries 4 -DelaySec 8 -TimeoutSec 3600
        if ((Get-Item $dest).Length -lt $MinBytes) { throw "Too small ($((Get-Item $dest).Length) bytes)" }
        if (-not (Test-NotHtml $dest)) { throw "Looks like HTML, not an installer." }
        if (-not (Test-InstallerMagic $dest)) { throw "Not a valid EXE/MSI (magic mismatch)." }
      }
      WriteLog ("Downloaded to {0} ({1:N0} bytes)" -f $dest, (Get-Item $dest).Length)
      return $dest
    } catch {
      WriteLog ("Source failed: {0} :: {1}" -f $u, $_.Exception.Message)
    }
  }
  throw ("All sources failed for {0} (size/magic/html checks failed or downloads unavailable)" -f $LocalName)
}

# Manual download / install helper (final fallback)
function Open-ManualAndWait {
  param(
    [string]$UrlPrimary,
    [string]$Message,
    [string]$TargetPath = "",
    [string]$UrlAlsoOpen = "",
    [int]$PollSeconds = 10,
    [int]$MaxMinutes = 90
  )
  Write-Warning $Message
  try {
    if ($UrlAlsoOpen) { Start-Process "chrome.exe" "--new-window $UrlPrimary"; Start-Process "chrome.exe" $UrlAlsoOpen | Out-Null }
    else { Start-Process "chrome.exe" "--new-window $UrlPrimary" | Out-Null }
  } catch { Start-Process $UrlPrimary | Out-Null }

  $deadline = (Get-Date).AddMinutes($MaxMinutes)
  if (-not $TargetPath) {
    Read-Host "When you're done installing, press ENTER here (or type S to skip)"
    return $true
  }

  while ((Get-Date) -lt $deadline) {
    if (Test-Path $TargetPath) { WriteLog "Manual file detected: $TargetPath"; return $true }
    Start-Sleep -Seconds $PollSeconds
  }
  return $false
}

# Chrome detection
function Test-ChromeInstalled {
  $paths=@("$env:ProgramFiles\Google\Chrome\Application\chrome.exe","$env:ProgramFiles(x86)\Google\Chrome\Application\chrome.exe")
  if($paths | Where-Object{Test-Path $_}){return $true}
  $keys=@("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall","HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall")
  foreach($k in $keys){ $hit=Get-ChildItem $k -ErrorAction SilentlyContinue | ForEach-Object{ try{Get-ItemProperty $_.PSPath}catch{} } | Where-Object{ $_.DisplayName -like "Google Chrome*" }; if($hit){return $true} }
  return $false
}

# Scheduled task helpers
function Create-ResumeTask {
  param([string]$ScriptPath)
  $escaped = $ScriptPath.Replace('"','\"')
  $action  = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$escaped`" -Resume"
  $user    = "$env:USERDOMAIN\$env:USERNAME"
  $cmdUser = "schtasks /Create /RU `"$user`" /RL HIGHEST /SC ONLOGON /TN `"$TaskName`" /TR `"$action`" /F"
  WriteLog "Creating resume task for user $user"
  try { cmd.exe /c $cmdUser | Out-Null; WriteLog "Created user resume task"; return }
  catch { WriteLog "User resume task failed: $($_.Exception.Message); trying SYSTEM" }
  $cmdSys  = "schtasks /Create /RU SYSTEM /RL HIGHEST /SC ONSTART /TN `"$TaskName`" /TR `"$action`" /F"
  cmd.exe /c $cmdSys | Out-Null
  WriteLog "Created SYSTEM resume task (fallback)"
}
function Remove-ResumeTask { try{ schtasks /Delete /TN $TaskName /F | Out-Null; WriteLog "Removed resume task" }catch{ WriteLog "No resume task to remove" } }

# -------------------- Light hardening --------------------
Try-Run {
  Add-MpPreference -ExclusionPath $Here -ErrorAction SilentlyContinue
  Add-MpPreference -ExclusionProcess "powershell.exe" -ErrorAction SilentlyContinue
  Write-Host "Added Defender exclusions for $Here and powershell.exe"
} "Defender exclusions"

# -------------------- Stage A: rename + DPI --------------------
$DesiredComputerName = Read-Host "Enter computer name (leave blank to keep current: $env:COMPUTERNAME)"
$needReboot = $false

if ($DesiredComputerName -and $DesiredComputerName -ne $env:COMPUTERNAME) {
  Try-Run { Rename-Computer -NewName $DesiredComputerName -Force } "Rename to $DesiredComputerName"
  $needReboot = $true
}

Try-Run {
  New-Item -Path "HKCU:\Control Panel\Desktop" -Force | Out-Null
  Set-ItemProperty "HKCU:\Control Panel\Desktop" -Name "LogPixels" -Type DWord -Value 120
  Set-ItemProperty "HKCU:\Control Panel\Desktop" -Name "Win8DpiScaling" -Type DWord -Value 1
  $needReboot = $true
} "Set DPI to 125%"

if (-not $Resume -and $needReboot) {
  $scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
  Try-Run { Create-ResumeTask -ScriptPath $scriptPath } "Create resume task"
  Write-Host "Rebooting now to apply rename/DPI. Script will auto-resume after you log in." -ForegroundColor Yellow
  WriteLog "Rebooting for rename/DPI"
  Restart-Computer -Force
  exit 0
}

# -------------------- Stage B: Resume-Phase (installs/config) --------------------
function Resume-Phase {

  WriteLog "Resume phase start. Waiting for network..."
  if (-not (Wait-Network -TimeoutSec 120)) { Write-Warning "Network not ready after wait; continuing." }

  # 1) Chrome
  if (Test-ChromeInstalled) {
    WriteLog "Chrome present; skip install"
  } else {
    Try-Run {
      if (Get-Command winget -ErrorAction SilentlyContinue) {
        winget install --id Google.Chrome --silent --accept-source-agreements --accept-package-agreements | Out-Null
      } else {
        $chrome = Get-FromSources -LocalName "GoogleChromeStandaloneEnterprise64.msi" -Sources @($FALLBACK_CHROME_MSI)
        Start-Process msiexec.exe -ArgumentList "/i `"$chrome`" /qn /norestart" -Wait
      }
    } "Install Chrome"
  }

  # 2) Default apps (interactive on Win11) — open minimized so PS stays visible
  Try-Run { Start-Process "ms-settings:defaultapps?apiname=Microsoft.Chrome" -WindowStyle Minimized; Start-Sleep 10 } "Open Default Apps (minimized)"

  # 3) Chrome sign-in (manual)
  Try-Run {
    Start-Process "chrome.exe" "--new-window https://accounts.google.com/ServiceLogin"
    Write-Host "`nPlease sign into Chrome as service@thetrivialcompany.com (enable sync if desired)." -ForegroundColor Yellow
    Read-Host "Press Enter here after you’ve finished signing in"
  } "Chrome account sign-in (manual)"

  # 4) Chrome Remote Desktop Host (auto → public → manual Drive/folder)
  Try-Run {
    $crd = $null
    try { $crd = Get-FromSources -LocalName "chromeremotedesktophost.msi" -Sources @($GDRIVE_CRD_MSI, $FALLBACK_CRD_MSI) } catch {}
    if ($crd -and (Test-Path $crd)) {
      $msiArgs = "/i `"$crd`" /qn /norestart"
      Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -NoNewWindow
    } else {
      Write-Warning "CRD auto-download failed. Opening vendor download + your Drive folder..."
      Open-ManualAndWait -UrlPrimary $FALLBACK_CRD_MSI -UrlAlsoOpen $GDRIVE_FOLDER_ROOT -Message "Download & install Chrome Remote Desktop Host. Close the installer when done, then press ENTER here." | Out-Null
    }
  } "Install Chrome Remote Desktop Host"

  # 5) .NET 3.5 (if needed)
  Try-Run { DISM /Online /Enable-Feature /FeatureName:NetFx3 /All /Quiet /NoRestart | Out-Null } ".NET 3.5"

  # 6) Python (auto via winget/Drive/public → manual page)
  Try-Run {
    $did = $false
    if (Get-Command winget -ErrorAction SilentlyContinue) {
      try { winget install --id Python.Python.3 --silent --accept-source-agreements --accept-package-agreements | Out-Null; $did=$true } catch {}
    }
    if (-not $did) {
      try {
        $py = Get-FromSources -LocalName "python-3.x-amd64.exe" -Sources @($GDRIVE_PY_EXE, $FALLBACK_PY_EXE)
        $ext = [IO.Path]::GetExtension($py).ToLower()
        if ($ext -eq ".msi") {
          Start-Process msiexec.exe -ArgumentList "/i `"$py`" /qn /norestart" -Wait
        } else {
          $ok=$false
          foreach($sw in @('/quiet InstallAllUsers=1 PrependPath=1','/quiet','/passive','/S','/VERYSILENT','/silent')){
            try{ Start-Process $py -ArgumentList $sw -Wait -NoNewWindow -ErrorAction Stop; $ok=$true; break }catch{}
          }
          if(-not $ok){
            Open-ManualAndWait -UrlPrimary "https://www.python.org/downloads/windows/" -Message "Download & install Python (3.x, 64-bit). Press ENTER here when finished." | Out-Null
          }
        }
      } catch {
        Open-ManualAndWait -UrlPrimary "https://www.python.org/downloads/windows/" -Message "Download & install Python (3.x, 64-bit). Press ENTER here when finished." | Out-Null
      }
    }
  } "Install Python (winget or fallback)"

  # 7) Machine Expert Basic (Drive auto → Downloads/Desktop → manual Drive file + folder)
  Try-Run {
    $mebExe = $null

    # 1) Try Drive auto (require ~450MB)
    try {
      $mebExe = Get-FromSources -LocalName "MachineExpertBasic_Setup.exe" -Sources @($GDRIVE_MEB_EXE) -MinBytes 450MB
    } catch {
      Write-Warning "Machine Expert Basic auto-download failed or incomplete."
    }

    # 2) Auto-check common locations
    if (-not $mebExe) {
      $candidates = @(
        (Join-Path $env:USERPROFILE 'Downloads\MachineExpertBasic_Setup.exe'),
        (Join-Path $env:USERPROFILE 'Desktop\MachineExpertBasic_Setup.exe')
      )
      foreach ($c in $candidates) {
        if (Test-Path $c -and (Get-Item $c).Length -ge 450MB -and (Test-InstallerMagic $c)) { $mebExe = $c; break }
      }
    }

    # 3) Manual Drive file + folder fallback (poll Downloads)
    if (-not $mebExe) {
      $targetPath = Join-Path $env:USERPROFILE 'Downloads\MachineExpertBasic_Setup.exe'
      $msg = "Drive tabs will open. Click YOUR file 'MachineExpertBasic_Setup.exe' → Download anyway, and save exactly as: $targetPath . The script will continue when the file appears."
      $ok = Open-ManualAndWait -UrlPrimary $GDRIVE_MEB_EXE -UrlAlsoOpen $GDRIVE_FOLDER_ROOT -Message $msg -TargetPath $targetPath
      if ($ok -and (Test-Path $targetPath) -and (Get-Item $targetPath).Length -ge 450MB -and (Test-InstallerMagic $targetPath)) {
        $mebExe = $targetPath
      }
    }

    if (-not $mebExe -or -not (Test-Path $mebExe)) { throw "Machine Expert EXE not available" }
    if ((Get-Item $mebExe).Length -lt 450MB) { throw "Downloaded EXE looks incomplete (< 450 MB): $mebExe" }

    # Try silent flags; fall back to interactive
    $ok = $false
    foreach ($sw in @('/S','/silent','/verysilent','/qn','/quiet','/s','/passive')) {
      try { Start-Process -FilePath $mebExe -ArgumentList $sw -Wait -NoNewWindow -ErrorAction Stop; $ok = $true; break } catch { }
    }
    if (-not $ok) {
      Write-Warning "Silent flags not accepted; launching interactive installer..."
      Start-Process -FilePath $mebExe -Wait
    }
  } "Install Machine Expert Basic (with manual Drive fallback)"

  # 8) Power / background policies
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
    New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Dsh" -Force | Out-Null
    Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Dsh" -Name "AllowNewsAndInterests" -Type DWord -Value 0
    New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Force | Out-Null
    Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" -Name "LetAppsRunInBackground" -Type DWord -Value 2
    Try{ Stop-Service WSearch -Force }Catch{}
    Set-Service WSearch -StartupType Disabled
    New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Force | Out-Null
    Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSync" -Type DWord -Value 1
  } "Reduce background activity"

  # 9) Firewall for CRD
  Try-Run {
    $hostExe = "$env:ProgramFiles\Google\Chrome Remote Desktop\CurrentVersion\remoting_host.exe"
    if(Test-Path $hostExe){
      New-NetFirewallRule -DisplayName "Chrome Remote Desktop Inbound" -Direction Inbound -Program $hostExe -Action Allow -Protocol TCP -Profile Any -ErrorAction SilentlyContinue | Out-Null
      New-NetFirewallRule -DisplayName "Chrome Remote Desktop Outbound" -Direction Outbound -Program $hostExe -Action Allow -Protocol TCP -Profile Any -ErrorAction SilentlyContinue | Out-Null
    }
  } "Firewall rules for CRD"

  # 10) Open CRD activation UI
  Try-Run { Start-Process "chrome.exe" "https://remotedesktop.google.com/access" } "Open CRD activation page"

  # Optional: upload log
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

  Remove-ResumeTask
  WriteLog "Resume phase complete."
  Write-Host "`nAll installs/config complete." -ForegroundColor Green
}

# Always run resume-phase now (if we needed a reboot we already exited above)
Resume-Phase
WriteLog "Done: $(Get-Date)"
