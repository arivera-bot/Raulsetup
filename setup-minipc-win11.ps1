<#
  setup-minipc-win11.ps1  — RUN AS ADMIN
  Staged provisioning w/ fallbacks & PS5.1-only tooling

  Stage A (normal run): optional rename + set DPI, schedule resume (user logon) and reboot if needed
  Stage B (resume or no-reboot): wait for network, download (with retries & fallbacks), install, configure, open Chrome sign-in then CRD UI
#>

param([switch]$Resume)

# -------------------- YOUR LINKS --------------------
$GDRIVE_PY_EXE   = "https://drive.google.com/file/d/1PANRP9dGXGla93-BdI3AfmnnDpKNblEG/view?usp=sharing"
$GDRIVE_MEB_ZIP  = "https://drive.google.com/file/d/19qg1MpLobyjUdFDmXnJhhdSJrM8kZ41B/view?usp=sharing"
$GDRIVE_CRD_MSI  = "https://drive.google.com/file/d/1G6IY2CRWAdnTLKcjStJGMQFELX85VEwI/view?usp=sharing"

# -------------------- PUBLIC FALLBACKS --------------------
# Chrome (standalone installer, quiet flag works)
$FALLBACK_CHROME_EXE = "https://dl.google.com/chrome/install/GoogleChromeStandaloneEnterprise64.msi"  # MSI is best for silent installs

# Chrome Remote Desktop Host MSI
$FALLBACK_CRD_MSI    = "https://dl.google.com/chrome-remote-desktop/chromeremotedesktophost.msi"

# Python (OPTIONAL: update this to a specific version you like)
$FALLBACK_PY_EXE     = "https://www.python.org/ftp/python/3.12.6/python-3.12.6-amd64.exe"

# Optional central log SMB share  e.g. "\\server\provision-logs"
$CentralLogShare = ""   # leave empty to skip
$TaskName = "ProvisionMiniPC_AutoResume"
$ErrorActionPreference = 'Stop'

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

function Invoke-WebRequest-Retry([string]$Uri,[string]$OutFile,[int]$Retries=3,[int]$DelaySec=5){
  for($i=1;$i -le $Retries;$i++){
    try{ Invoke-WebRequest -UseBasicParsing -Uri $Uri -OutFile $OutFile -TimeoutSec 240; WriteLog ("Downloaded {0} -> {1}" -f $Uri,$OutFile); return }
    catch{ WriteLog ("Attempt {0}/{1} failed: {2}" -f $i,$Retries,$_.Exception.Message); if($i -eq $Retries){throw}; Start-Sleep $DelaySec }
  }
}

# Google Drive downloader (uses Invoke-WebRequest + session cookie)
function Download-GoogleDrive([string]$ShareUrl,[string]$DestinationPath){
  if(-not $ShareUrl){ throw "No URL supplied." }
  if($ShareUrl -match '/d/([A-Za-z0-9_-]+)'){ $id=$Matches[1] }
  elseif($ShareUrl -match 'id=([A-Za-z0-9_-]+)'){ $id=$Matches[1] }
  else{ throw "Couldn't parse Google Drive ID from $ShareUrl" }

  $base = "https://docs.google.com/uc?export=download&id=$id"
  $sess = $null
  $r1 = Invoke-WebRequest -UseBasicParsing -Uri $base -SessionVariable sess

  if ($r1.Headers.'Content-Type' -and $r1.Headers.'Content-Type' -notlike 'text/html*') {
    Invoke-WebRequest -UseBasicParsing -Uri $base -WebSession $sess -OutFile $DestinationPath
    return
  }

  $html = $r1.RawContent
  $token = $null
  if ($html -match 'confirm=([0-9A-Za-z_-]+)') { $token = $Matches[1] }
  elseif ($r1.Content -match 'name="confirm" value="([0-9A-Za-z_-]+)"') { $token = $Matches[1] }
  if (-not $token) {
    foreach ($cookie in $sess.Cookies.GetCookies($base)) {
      if ($cookie.Name -like 'download_warning*') { $token = $cookie.Value; break }
    }
  }
  if (-not $token) { throw "Could not obtain Drive confirm token (large file)." }

  $url2 = "$base&confirm=$token"
  Invoke-WebRequest -UseBasicParsing -Uri $url2 -WebSession $sess -OutFile $DestinationPath
}

# Downloads with multiple fallbacks (first non-empty URL that works wins)
function Get-FromSources {
  param(
    [string]$LocalName,
    [string[]]$Sources # ordered list of URLs (Drive or direct)
  )
  $local = Join-Path $Here $LocalName
  if (Test-Path $local) { WriteLog "Using local $local"; return $local }

  $dest = Join-Path $env:TEMP $LocalName
  foreach ($u in $Sources) {
    if (-not $u) { continue }
    try {
      if ($u -like "*drive.google.com*") {
        WriteLog "Downloading from Drive: $u"
        Download-GoogleDrive -ShareUrl $u -DestinationPath $dest
      } else {
        WriteLog "Downloading: $u"
        Invoke-WebRequest-Retry -Uri $u -OutFile $dest -Retries 3 -DelaySec 6
      }
      if (Test-Path $dest) { return $dest }
    } catch {
      WriteLog ("Source failed: {0} :: {1}" -f $u, $_.Exception.Message)
    }
  }
  throw ("All sources failed for {0}" -f $LocalName)
}

# Chrome detection
function Test-ChromeInstalled {
  $paths=@("$env:ProgramFiles\Google\Chrome\Application\chrome.exe","$env:ProgramFiles(x86)\Google\Chrome\Application\chrome.exe")
  if($paths | Where-Object{Test-Path $_}){return $true}
  $keys=@("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall","HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall")
  foreach($k in $keys){ $hit=Get-ChildItem $k -ErrorAction SilentlyContinue | ForEach-Object{ try{Get-ItemProperty $_.PSPath}catch{} } | Where-Object{ $_.DisplayName -like "Google Chrome*" }; if($hit){return $true} }
  return $false
}

# Scheduled task helpers (user ONLOGON; fallback SYSTEM ONSTART)
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
        $chrome = Get-FromSources -LocalName "GoogleChromeStandaloneEnterprise64.msi" -Sources @($FALLBACK_CHROME_EXE)
        Start-Process msiexec.exe -ArgumentList "/i `"$chrome`" /qn /norestart" -Wait
      }
    } "Install Chrome"
  }

  # 2) Default apps (Win11 is interactive). Open minimized.
  Try-Run { Start-Process "ms-settings:defaultapps?apiname=Microsoft.Chrome" -WindowStyle Minimized; Start-Sleep 10 } "Open Default Apps (minimized)"

  # 3) Prompt to sign into Chrome (manual)
  Try-Run {
    Start-Process "chrome.exe" "--new-window https://accounts.google.com/ServiceLogin"
    Write-Host "`nPlease sign into Chrome as service@thetrivialcompany.com (enable sync if desired)." -ForegroundColor Yellow
    Read-Host "Press Enter here after you’ve finished signing in"
  } "Chrome account sign-in (manual)"

  # 4) Chrome Remote Desktop Host
  Try-Run {
    $crd = Get-FromSources -LocalName "chromeremotedesktophost.msi" -Sources @($GDRIVE_CRD_MSI, $FALLBACK_CRD_MSI)
    Start-Process msiexec.exe -ArgumentList "/i `"$crd`" /qn /norestart" -Wait
  } "Install Chrome Remote Desktop Host"

  # 5) .NET 3.5 (if needed)
  Try-Run { DISM /Online /Enable-Feature /FeatureName:NetFx3 /All /Quiet /NoRestart | Out-Null } ".NET 3.5"

  # 6) Python
  Try-Run {
    $did = $false
    if (Get-Command winget -ErrorAction SilentlyContinue) {
      try { winget install --id Python.Python.3 --silent --accept-source-agreements --accept-package-agreements | Out-Null; $did=$true } catch {}
    }
    if (-not $did) {
      $py = Get-FromSources -LocalName "python_installer.exe" -Sources @($GDRIVE_PY_EXE, $FALLBACK_PY_EXE)
      $ext = [IO.Path]::GetExtension($py).ToLower()
      if ($ext -eq ".msi") { Start-Process msiexec.exe -ArgumentList "/i `"$py`" /qn /norestart" -Wait }
      else {
        $ok=$false
        foreach($sw in @('/quiet InstallAllUsers=1 PrependPath=1','/quiet','/passive','/S','/VERYSILENT','/silent')){
          try{ Start-Process $py -ArgumentList $sw -Wait -NoNewWindow -ErrorAction Stop; $ok=$true; break }catch{}
        }
        if(-not $ok){ Write-Warning "Python installer may need interactive run; check flags." }
      }
    }
  } "Install Python (winget or fallback)"

  # 7) Machine Expert Basic
  Try-Run {
    $meb = Get-FromSources -LocalName "MachineExpertBasic_V1.2_SP1.zip" -Sources @($GDRIVE_MEB_ZIP)
    $dst = Join-Path $Here "MachineExpertBasic_Extracted"
    if(Test-Path $dst){ Remove-Item $dst -Recurse -Force }
    Expand-Archive -Path $meb -DestinationPath $dst -Force
    $msi = Get-ChildItem $dst -Recurse -Filter *.msi -ErrorAction SilentlyContinue | Select-Object -First 1
    $exe = Get-ChildItem $dst -Recurse -Filter *.exe -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'setup|install|machine|expert' } | Select-Object -First 1
    if($msi){ Start-Process msiexec.exe -ArgumentList "/i `"$($msi.FullName)`" /qn /norestart" -Wait }
    elseif($exe){
      $ok=$false; foreach($sw in @('/S','/silent','/verysilent','/qn','/s')){ try{ Start-Process $exe.FullName -ArgumentList $sw -Wait -NoNewWindow; $ok=$true; break }catch{} }
      if(-not $ok){ Write-Warning "Machine Expert installer might need interactive run." }
    } else { throw "No installer found inside the Machine Expert ZIP." }
  } "Install Machine Expert Basic"

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
    New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" -Force | Out-Null
    Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" -Name "AllowNewsAndInterests" -Type DWord -Value 0
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

# Always run resume-phase now (if we needed a reboot we already exited)
Resume-Phase

WriteLog "Done: $(Get-Date)"
