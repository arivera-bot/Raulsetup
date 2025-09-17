<#
  setup-minipc-win11.ps1 — RUN AS ADMIN (PowerShell 5.1)
  Goal: install needed apps, keep system always-on, and halt Windows Update.
  Defaults: NO DPI/font change unless you opt-in; rename optional.
#>

param([switch]$Resume)

# ====== YOUR LINKS ======
$GDRIVE_PY_EXE      = "https://drive.google.com/file/d/1PANRP9dGXGla93-BdI3AfmnnDpKNblEG/view?usp=sharing"
$GDRIVE_MEB_EXE     = "https://drive.google.com/file/d/1CfLdcXN1DqRZDGCWsPxpo3XFS7kbmMrN/view?usp=sharing"
$GDRIVE_CRD_MSI     = "https://drive.google.com/file/d/1G6IY2CRWAdnTLKcjStJGMQFELX85VEwI/view?usp=sharing"
$GDRIVE_FOLDER_ROOT = "https://drive.google.com/drive/folders/1FuLqB892C_6ktjGnyV-X4qPQqeDr0-D8?usp=drive_link"

# Public fallbacks
$FALLBACK_CHROME_MSI = "https://dl.google.com/chrome/install/GoogleChromeStandaloneEnterprise64.msi"
$FALLBACK_CRD_MSI    = "https://dl.google.com/edgedl/chrome-remote-desktop/chromeremotedesktophost.msi"  # fixed
$FALLBACK_PY_EXE     = "https://www.python.org/ftp/python/3.12.6/python-3.12.6-amd64.exe"

# ====== Setup ======
$TaskName = "ProvisionMiniPC_AutoResume"
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path; if (-not $Here) { $Here = $env:TEMP }
$Log  = Join-Path $Here "setup-mini-pc.log"
"=== Run: $(Get-Date) on $env:COMPUTERNAME (Resume=$Resume) ===" | Out-File $Log -Append -Encoding utf8
function WriteLog($m){ $m | Out-File -FilePath $Log -Append -Encoding utf8; Write-Host $m }

# Admin check
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){ Write-Error "Run this script as Administrator."; exit 1 }

# ====== Helpers ======
function Wait-Network([int]$TimeoutSec=120){
  $sw=[Diagnostics.Stopwatch]::StartNew()
  while($sw.Elapsed.TotalSeconds -lt $TimeoutSec){
    try{ [void][System.Net.Dns]::GetHostEntry("www.google.com"); WriteLog "Network ready"; return $true }catch{ Start-Sleep 3 }
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
    }catch{ WriteLog ("Attempt {0}/{1} failed: {2}" -f $i,$Retries,$_.Exception.Message); if($i -eq $Retries){ throw }; Start-Sleep $DelaySec }
  }
}
function Test-InstallerMagic([string]$Path){
  if (-not (Test-Path $Path)) { return $false }
  try{
    $fs=[IO.File]::Open($Path,'Open','Read','Read'); $br=New-Object IO.BinaryReader($fs)
    $b=$br.ReadBytes(8); $br.Dispose(); $fs.Dispose()
    if($b.Length -lt 2){return $false}
    if($b[0] -eq 0x4D -and $b[1] -eq 0x5A){return $true} # EXE
    if($b.Length -ge 8 -and $b[0]-eq 0xD0 -and $b[1]-eq 0xCF -and $b[2]-eq 0x11 -and $b[3]-eq 0xE0 -and $b[4]-eq 0xA1 -and $b[5]-eq 0xB1 -and $b[6]-eq 0x1A -and $b[7]-eq 0xE1){return $true} # MSI
  }catch{}
  return $false
}
function Test-NotHtml([string]$Path){
  if (-not (Test-Path $Path)) { return $false }
  try{
    $bytes=[IO.File]::ReadAllBytes($Path); if($bytes.Length -lt 32){return $false}
    $sliceLen=[Math]::Min(2048,$bytes.Length)
    $txt=[Text.Encoding]::ASCII.GetString($bytes,0,$sliceLen)
    if($txt -match '<\!DOCTYPE\s+html' -or $txt -match '<html' -or $txt -match 'Google Drive' -or $txt -match 'quota exceeded' -or $txt -match 'Sign in'){return $false}
    return $true
  }catch{ return $false }
}
function Download-GoogleDrive([string]$ShareUrl,[string]$DestinationPath,[int]$TimeoutSec=3600,[int]$MinBytes=1MB){
  if(-not $ShareUrl){ throw "No URL" }
  $id=$null
  if($ShareUrl -match '/d/([A-Za-z0-9_-]+)'){ $id=$Matches[1] } elseif($ShareUrl -match 'id=([A-Za-z0-9_-]+)'){ $id=$Matches[1] } else{ throw "Bad Drive URL: $ShareUrl" }
  $base="https://docs.google.com/uc?export=download&id=$id"; if(Test-Path $DestinationPath){ Remove-Item $DestinationPath -Force -ErrorAction SilentlyContinue }
  $headers=@{'User-Agent'='Mozilla/5.0';'Accept'='*/*'}
  $sess=$null
  $r1=Invoke-WebRequest -UseBasicParsing -Uri $base -Headers $headers -SessionVariable sess -TimeoutSec $TimeoutSec
  if($r1.Headers['Content-Type'] -and $r1.Headers['Content-Type'] -notlike 'text/html*'){
    Invoke-WebRequest -UseBasicParsing -Uri $base -WebSession $sess -OutFile $DestinationPath -Headers $headers -TimeoutSec $TimeoutSec
  } else {
    $token=$null
    foreach($cookie in $sess.Cookies.GetCookies([Uri]$base)){ if($cookie.Name -like 'download_warning*'){ $token=$cookie.Value; break } }
    if(-not $token){
      $html=$r1.Content
      if($html -match 'confirm=([0-9A-Za-z_-]+)'){ $token=$Matches[1] }
      elseif($html -match 'name="confirm"\s+value="([0-9A-Za-z_-]+)"'){ $token=$Matches[1] }
      elseif($html -match 'href="[^"]*?confirm=([0-9A-Za-z_-]+)[^"]*"'){ $token=$Matches[1] }
    }
    if(-not $token){ throw "No Drive confirm token (permissions/quota?)" }
    $dl="$base&confirm=$token"
    Invoke-WebRequest -UseBasicParsing -Uri $dl -WebSession $sess -OutFile $DestinationPath -Headers $headers -TimeoutSec $TimeoutSec
  }
  if(-not (Test-Path $DestinationPath)){ throw "No file" }
  $len=(Get-Item $DestinationPath).Length
  if($len -lt $MinBytes){ throw "Too small ($len bytes)" }
  if(-not (Test-NotHtml $DestinationPath)){ throw "Got HTML instead of binary" }
  if(-not (Test-InstallerMagic $DestinationPath)){ throw "Not a valid EXE/MSI" }
  $stable=0;$last=-1
  while($stable -lt 3){ $sz=(Get-Item $DestinationPath).Length; if($sz -eq $last -and $sz -ge $MinBytes){$stable++}else{$stable=0;$last=$sz}; Start-Sleep 2 }
}
function Get-FromSources([string]$LocalName,[string[]]$Sources,[int]$MinBytes=1MB){
  $local=Join-Path $Here $LocalName
  if(Test-Path $local -and (Get-Item $local).Length -ge $MinBytes -and (Test-NotHtml $local) -and (Test-InstallerMagic $local)){ WriteLog "Using local $local"; return $local }
  $dest=Join-Path $env:TEMP $LocalName
  foreach($u in $Sources){
    if(-not $u){ continue }
    try{
      if(Test-Path $dest){ Remove-Item $dest -Force -ErrorAction SilentlyContinue }
      if($u -like "*drive.google.com*"){ WriteLog "Drive: $u"; Download-GoogleDrive -ShareUrl $u -DestinationPath $dest -TimeoutSec 3600 -MinBytes $MinBytes }
      else{ WriteLog "HTTP: $u"; Invoke-WebRequest-Retry -Uri $u -OutFile $dest -Retries 4 -DelaySec 8 -TimeoutSec 3600; if((Get-Item $dest).Length -lt $MinBytes){ throw "Too small" }; if(-not (Test-NotHtml $dest)){ throw "HTML page" }; if(-not (Test-InstallerMagic $dest)){ throw "Bad magic" } }
      WriteLog ("Downloaded {0} bytes to {1}" -f (Get-Item $dest).Length,$dest); return $dest
    }catch{ WriteLog ("Source failed: {0} :: {1}" -f $u,$_.Exception.Message) }
  }
  throw ("All sources failed for $LocalName")
}
function Open-ManualAndWait([string]$UrlPrimary,[string]$Message,[string]$TargetPath="",[string]$UrlAlsoOpen="",[int]$PollSeconds=10,[int]$MaxMinutes=90){
  Write-Warning $Message
  try{ if($UrlAlsoOpen){ Start-Process "chrome.exe" "--new-window $UrlPrimary"; Start-Process "chrome.exe" $UrlAlsoOpen | Out-Null } else { Start-Process "chrome.exe" "--new-window $UrlPrimary" | Out-Null } }catch{ Start-Process $UrlPrimary | Out-Null }
  $deadline=(Get-Date).AddMinutes($MaxMinutes)
  if(-not $TargetPath){ Read-Host "When done, press ENTER (or type S to skip)"; return $true }
  while((Get-Date) -lt $deadline){ if(Test-Path $TargetPath){ WriteLog "Detected: $TargetPath"; return $true }; Start-Sleep -Seconds $PollSeconds }
  return $false
}
function Try-Run($sb,$desc){ try{ & $sb; WriteLog "OK: $desc" } catch{ WriteLog ("ERR: {0} :: {1}" -f $desc,$_.Exception.Message); Write-Warning "Failed: $desc -> $($_.Exception.Message)" } }

# Chrome detection
function Test-ChromeInstalled {
  $paths=@("$env:ProgramFiles\Google\Chrome\Application\chrome.exe","$env:ProgramFiles(x86)\Google\Chrome\Application\chrome.exe")
  if($paths | Where-Object{Test-Path $_}){return $true}
  $keys=@("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall","HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall")
  foreach($k in $keys){ $hit=Get-ChildItem $k -ErrorAction SilentlyContinue | ForEach-Object{ try{Get-ItemProperty $_.PSPath}catch{} } | Where-Object{ $_.DisplayName -like "Google Chrome*" }; if($hit){return $true} }
  return $false
}

# Scheduled-task helpers
function Create-ResumeTask([string]$ScriptPath){
  $escaped=$ScriptPath.Replace('"','\"')
  $action="powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$escaped`" -Resume"
  $user="$env:USERDOMAIN\$env:USERNAME"
  $cmdUser="schtasks /Create /RU `"$user`" /RL HIGHEST /SC ONLOGON /TN `"$TaskName`" /TR `"$action`" /F"
  try{ cmd.exe /c $cmdUser | Out-Null; WriteLog "Resume task (user) created"; return }catch{ WriteLog "User resume task failed; trying SYSTEM" }
  $cmdSys="schtasks /Create /RU SYSTEM /RL HIGHEST /SC ONSTART /TN `"$TaskName`" /TR `"$action`" /F"
  cmd.exe /c $cmdSys | Out-Null; WriteLog "Resume task (SYSTEM) created"
}
function Remove-ResumeTask { try{ schtasks /Delete /TN $TaskName /F | Out-Null; WriteLog "Resume task removed" }catch{ WriteLog "No resume task to remove" } }

# ====== Light hardening & Defender exclusions ======
Try-Run { Add-MpPreference -ExclusionPath $Here -ErrorAction SilentlyContinue; Add-MpPreference -ExclusionProcess "powershell.exe" -ErrorAction SilentlyContinue; Write-Host "Defender exclusions set." } "Defender exclusions"

# ====== Stage A: rename + optional DPI ======
$needReboot=$false
if (-not $Resume){
  $DesiredComputerName = Read-Host "Enter computer name (blank keeps $env:COMPUTERNAME)"
  if ($DesiredComputerName -and $DesiredComputerName -ne $env:COMPUTERNAME) { Try-Run { Rename-Computer -NewName $DesiredComputerName -Force } "Rename to $DesiredComputerName"; $needReboot=$true }
  $wantDPI = Read-Host "Set display scaling to 125%? (Y/N, default N)"
  if ($wantDPI -match '^[Yy]'){
    Try-Run {
      New-Item -Path "HKCU:\Control Panel\Desktop" -Force | Out-Null
      Set-ItemProperty "HKCU:\Control Panel\Desktop" -Name "LogPixels" -Type DWord -Value 120
      Set-ItemProperty "HKCU:\Control Panel\Desktop" -Name "Win8DpiScaling" -Type DWord -Value 1
    } "Set DPI to 125%"
    $needReboot=$true
  } else {
    # Ensure default 100% for readability if it was previously changed
    Try-Run {
      New-Item -Path "HKCU:\Control Panel\Desktop" -Force | Out-Null
      Set-ItemProperty "HKCU:\Control Panel\Desktop" -Name "Win8DpiScaling" -Type DWord -Value 0
      Remove-ItemProperty "HKCU:\Control Panel\Desktop" -Name "LogPixels" -ErrorAction SilentlyContinue
    } "Ensure DPI 100% (no scaling)"
  }
  if ($needReboot){
    $scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
    Try-Run { Create-ResumeTask -ScriptPath $scriptPath } "Create resume task"
    Write-Host "Rebooting to apply changes… (script will auto-resume)" -ForegroundColor Yellow
    Restart-Computer -Force; exit 0
  }
}

# ====== Stage B: installs & config ======
function Resume-Phase {

  WriteLog "=== RESUME PHASE START ==="
  if (-not (Wait-Network -TimeoutSec 120)) { Write-Warning "Network not ready; continuing." }

  # 1) Chrome
  if (Test-ChromeInstalled) { WriteLog "Chrome present; skipping install" }
  else {
    Try-Run {
      if (Get-Command winget -ErrorAction SilentlyContinue) {
        winget install --id Google.Chrome --silent --accept-source-agreements --accept-package-agreements | Out-Null
      } else {
        $chrome = Get-FromSources -LocalName "GoogleChromeStandaloneEnterprise64.msi" -Sources @($FALLBACK_CHROME_MSI)
        Start-Process msiexec.exe -ArgumentList "/i `"$chrome`" /qn /norestart" -Wait
      }
    } "Install Chrome"
  }

  # 2) Default app prompt (Win11)
  Try-Run { Start-Process "ms-settings:defaultapps?apiname=Microsoft.Chrome" -WindowStyle Minimized; Start-Sleep 5 } "Open Default Apps (minimized)"

  # 3) Chrome sign-in (manual)
  Try-Run {
    Start-Process "chrome.exe" "--new-window https://accounts.google.com/ServiceLogin"
    Write-Host "`nPlease sign into Chrome as service@thetrivialcompany.com (enable sync)."
    Read-Host "Press ENTER here after you’ve finished signing in"
  } "Chrome account sign-in"

  # 4) Chrome Remote Desktop Host
  Try-Run {
    $crdLocal = $null
    try { $crdLocal = Get-FromSources -LocalName "chromeremotedesktophost.msi" -Sources @($GDRIVE_CRD_MSI, $FALLBACK_CRD_MSI) } catch {}
    if (-not $crdLocal) {
      $target = Join-Path $env:USERPROFILE 'Downloads\chromeremotedesktophost.msi'
      $msg = "Download CRD Host and save as: $target . Script will continue when the file appears."
      [void](Open-ManualAndWait -UrlPrimary $FALLBACK_CRD_MSI -UrlAlsoOpen $GDRIVE_FOLDER_ROOT -Message $msg -TargetPath $target)
      if (Test-Path $target) { $crdLocal = $target }
    }
    if ($crdLocal) {
      $args = "/i `"$crdLocal`" /qn /norestart"
      WriteLog "Installing CRD Host via msiexec $args"
      Start-Process -FilePath "msiexec.exe" -ArgumentList $args -Wait -NoNewWindow
    }
    # Verify install
    $hostExe = "$env:ProgramFiles\Google\Chrome Remote Desktop\CurrentVersion\remoting_host.exe"
    $svc = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "Chrome Remote Desktop*" }
    if ((Test-Path $hostExe) -or $svc) { WriteLog "CRD Host appears installed." }
    else {
      Write-Warning "CRD Host not detected after install. Launching vendor page again for interactive install…"
      Start-Process "chrome.exe" "--new-window https://remotedesktop.google.com/access" | Out-Null
    }
  } "Install Chrome Remote Desktop Host"

  # 5) .NET 3.5
  Try-Run { DISM /Online /Enable-Feature /FeatureName:NetFx3 /All /Quiet /NoRestart | Out-Null } ".NET 3.5"

  # 6) Python (detect → silent install → verify)
  Try-Run {
    function Test-Python { return (Get-Command python -ErrorAction SilentlyContinue) -or (Get-Command py -ErrorAction SilentlyContinue) }
    if (Test-Python) { WriteLog "Python already present; skipping" }
    else {
      $py = $null
      try { $py = Get-FromSources -LocalName "python_installer.exe" -Sources @($GDRIVE_PY_EXE, $FALLBACK_PY_EXE) } catch {}
      if (-not $py) {
        Write-Warning "Python not downloaded automatically; opening downloads page."
        [void](Open-ManualAndWait -UrlPrimary "https://www.python.org/downloads/windows/" -Message "Download Python 3.x (64-bit) and run it. Press ENTER here when done.")
      } else {
        $silent = "/quiet InstallAllUsers=1 PrependPath=1 Include_test=0"
        WriteLog "Running Python installer silently: $py $silent"
        Start-Process -FilePath $py -ArgumentList $silent -Wait -NoNewWindow
      }
      if (Test-Python) { WriteLog "Python installed and in PATH." } else { Write-Warning "Python still not detected; you can install it later manually." }
    }
  } "Install Python"

  # 7) Machine Expert Basic (robust)
  Try-Run {
    function Test-MEBFile([string]$p){ if (-not (Test-Path $p)) { return $false }; $len=((Get-Item $p).Length -ge 450MB); $mag=(Test-InstallerMagic $p); return ($len -and $mag) }
    $meb = $null
    try { $meb = Get-FromSources -LocalName "MachineExpertBasic_Setup.exe" -Sources @($GDRIVE_MEB_EXE) -MinBytes 450MB } catch { Write-Warning "MEB auto-download failed." }
    if (-not $meb) {
      foreach($c in @((Join-Path $env:USERPROFILE 'Downloads\MachineExpertBasic_Setup.exe'), (Join-Path $env:USERPROFILE 'Downloads\MachineExpertBasic_Setup'), (Join-Path $env:USERPROFILE 'Desktop\MachineExpertBasic_Setup.exe'))){ if (Test-MEBFile $c){ $meb=$c; break } }
    }
    if (-not $meb) {
      $target = Join-Path $env:USERPROFILE 'Downloads\MachineExpertBasic_Setup.exe'
      $msg = "Drive will open. Click 'Download anyway' and save exactly as: $target . Script continues when file appears."
      [void](Open-ManualAndWait -UrlPrimary $GDRIVE_MEB_EXE -UrlAlsoOpen $GDRIVE_FOLDER_ROOT -Message $msg -TargetPath $target)
      if (Test-MEBFile $target){ $meb=$target }
    }
    if (-not $meb){ throw "Machine Expert EXE not available" }
    $ok=$false
    foreach($sw in @('/S','/silent','/verysilent','/qn','/quiet','/s','/passive')){
      try{ Start-Process -FilePath $meb -ArgumentList $sw -Wait -NoNewWindow -ErrorAction Stop; $ok=$true; break }catch{}
    }
    if (-not $ok){ WriteLog "Launching Machine Expert interactively…"; Start-Process -FilePath $meb -Wait }
  } "Install Machine Expert Basic"

  # 8) Power: keep awake forever
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

  # 9) Halt Windows Update aggressively
  Try-Run {
    # Policy keys
    New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Force | Out-Null
    New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
    Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Type DWord -Value 1
    Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Type DWord -Value 2
    # Disable driver updates via WU
    New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Force | Out-Null
    Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -Type DWord -Value 1
    # Consumer content off
    New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
    Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1
    # Disable Windows Search & OneDrive sync
    Try{ Stop-Service WSearch -Force }Catch{}
    Set-Service WSearch -StartupType Disabled
    New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Force | Out-Null
    Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSync" -Type DWord -Value 1
    # Stop/disable update services
    foreach($svcName in @("wuauserv","UsoSvc","BITS","DoSvc","WaaSMedicSvc")){
      $svc=Get-Service -Name $svcName -ErrorAction SilentlyContinue
      if($svc){ try{ Stop-Service $svc -Force -ErrorAction SilentlyContinue }catch{}; try{ Set-Service $svc -StartupType Disabled }catch{} }
    }
    # Disable Update Orchestrator & related scheduled tasks
    $taskPaths=@("\Microsoft\Windows\WindowsUpdate\","\Microsoft\Windows\UpdateOrchestrator\","\Microsoft\Windows\WaaSMedic\")
    foreach($tp in $taskPaths){
      $tasks=Get-ScheduledTask -TaskPath $tp -ErrorAction SilentlyContinue
      foreach($t in $tasks){ try{ Disable-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction SilentlyContinue }catch{} }
    }
  } "Halt Windows Update (services + policies + tasks)"

  # 10) Firewall for CRD + open activation page
  Try-Run {
    $hostExe = "$env:ProgramFiles\Google\Chrome Remote Desktop\CurrentVersion\remoting_host.exe"
    if(Test-Path $hostExe){
      New-NetFirewallRule -DisplayName "Chrome Remote Desktop Inbound" -Direction Inbound -Program $hostExe -Action Allow -Protocol TCP -Profile Any -ErrorAction SilentlyContinue | Out-Null
      New-NetFirewallRule -DisplayName "Chrome Remote Desktop Outbound" -Direction Outbound -Program $hostExe -Action Allow -Protocol TCP -Profile Any -ErrorAction SilentlyContinue | Out-Null
    }
    Start-Process "chrome.exe" "https://remotedesktop.google.com/access" | Out-Null
  } "CRD firewall + open access page"

  Remove-ResumeTask
  WriteLog "=== RESUME PHASE COMPLETE ==="
  Write-Host "`nAll installs/config complete." -ForegroundColor Green
}

# Run resume-phase now
Resume-Phase
WriteLog "Done: $(Get-Date)"
