<#
  setup-minipc-win11.ps1  — RUN AS ADMIN
  Staged provisioning:
    - Stage A (normal run): optional rename + set DPI, schedule resume (user logon) and reboot if needed
    - Stage B (resume or no-reboot): waits for network, downloads (with retries), installs, configures, opens CRD UI
#>

param([switch]$Resume)

# -------------------- CONFIG --------------------
$GDRIVE_PY_EXE   = "https://drive.google.com/file/d/1PANRP9dGXGla93-BdI3AfmnnDpKNblEG/view?usp=sharing"
$GDRIVE_MEB_ZIP  = "https://drive.google.com/file/d/19qg1MpLobyjUdFDmXnJhhdSJrM8kZ41B/view?usp=sharing"
$GDRIVE_CRD_MSI  = "https://drive.google.com/file/d/1G6IY2CRWAdnTLKcjStJGMQFELX85VEwI/view?usp=sharing"

# Optional: upload log to a share like \\server\provision-logs
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
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Write-Error "Run as Administrator."; exit 1 }

# -------------------- Scheduled task helpers --------------------
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

function Remove-ResumeTask {
  try { schtasks /Delete /TN $TaskName /F | Out-Null; WriteLog "Removed resume task" } catch { WriteLog "No resume task to remove" }
}

# -------------------- Network + Download helpers --------------------
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
    try{ Invoke-WebRequest -UseBasicParsing -Uri $Uri -OutFile $OutFile -TimeoutSec 120; WriteLog ("Downloaded {0} -> {1}" -f $Uri,$OutFile); return }
    catch{ WriteLog ("Attempt {0}/{1} failed: {2}" -f $i,$Retries,$_.Exception.Message); if($i -eq $Retries){throw}; Start-Sleep $DelaySec }
  }
}

function Download-GoogleDrive([string]$ShareUrl,[string]$DestinationPath){
  if(-not $ShareUrl){ throw "No URL" }
  if($ShareUrl -match '/d/([A-Za-z0-9_-]+)'){ $id=$Matches[1] } elseif($ShareUrl -match 'id=([A-Za-z0-9_-]+)'){ $id=$Matches[1] } else{ throw "Bad Drive URL: $ShareUrl" }
  $base="https://docs.google.com/uc?export=download&id=$id"
  $h=New-Object System.Net.Http.HttpClientHandler; $h.AllowAutoRedirect=$true
  $c=New-Object System.Net.Http.HttpClient($h); $r=$c.GetAsync($base).Result
  $ct=$null; try{$ct=$r.Content.Headers.ContentType.MediaType}catch{}
  $html=$r.Content.ReadAsStringAsync().Result
  if($ct -and $ct -ne "text/html"){ [IO.File]::WriteAllBytes($DestinationPath,$r.Content.ReadAsByteArrayAsync().Result); WriteLog "Drive direct -> $DestinationPath"; return }
  $token=$null
  if($html -match 'confirm=([0-9A-Za-z_-]+)'){ $token=$Matches[1] }
  elseif($html -match 'name="confirm" value="([0-9A-Za-z_-]+)"'){ $token=$Matches[1] }
  if(-not $token){
    $jar=New-Object System.Net.CookieContainer
    $h2=New-Object System.Net.Http.HttpClientHandler; $h2.CookieContainer=$jar; $h2.AllowAutoRedirect=$true
    $c2=New-Object System.Net.Http.HttpClient($h2); $null=$c2.GetAsync($base).Result
    foreach($ck in $jar.GetCookies([Uri]$base)){ if($ck.Name -like "download_warning*"){ $token=$ck.Value; break } }
  }
  if(-not $token){ throw "Drive confirm token not found" }
  $r2=$c.GetAsync("$base&confirm=$token").Result
  if($r2.IsSuccessStatusCode){ [IO.File]::WriteAllBytes($DestinationPath,$r2.Content.ReadAsByteArrayAsync().Result); WriteLog "Drive confirmed -> $DestinationPath" } else{ throw "Drive download failed: $($r2.StatusCode)" }
}

function Get-Or-Download([string]$LocalName,[string]$Url){
  $local=Join-Path $Here $LocalName
  if(Test-Path $local){ WriteLog "Using local $local"; return $local }
  $dest=Join-Path $env:TEMP $LocalName
  if($Url -like "*drive.google.com*"){ WriteLog "Downloading $LocalName from Drive"; Download-GoogleDrive -ShareUrl $Url -DestinationPath $dest; return $dest }
  Invoke-WebRequest-Retry -Uri $Url -OutFile $dest -Retries 3 -DelaySec 5; return $dest
}

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

# Set DPI to 125% for current user (requires sign-out/reboot to fully apply)
Try-Run {
  New-Item -Path "HKCU:\Control Panel\Desktop" -Force | Out-Null
  Set-ItemProperty "HKCU:\Control Panel\Desktop" -Name "LogPixels" -Type DWord -Value 120
  Set-ItemProperty "HKCU:\Control Panel\Desktop" -Name "Win8DpiScaling" -Type DWord -Value 1
  $needReboot = $true
} "Set DPI to 125%"

if (-not $Resume -and $needReboot) {
  Try-Run { Create-ResumeTask -ScriptPath ($PSCommandPath ?? $MyInvocation.MyCommand.Path) } "Create resume task"
  Write-Host "Rebooting now to apply rename/DPI. Script will auto-resume after you log in." -ForegroundColor Yellow
  WriteLog "Rebooting for rename/DPI"
  Restart-Computer -Force
  exit 0
}

# -------------------- Stage B: Resume-Phase (installs/config) --------------------
function Resume-Phase {

  WriteLog "Resume phase start. Waiting for network..."
  if (-not (Wait-Network -TimeoutSec 120)) { Write-Warning "Network not ready after wait; continuing." }

  # Chrome (skip if present)
  function Test-ChromeInstalled {
    $paths=@("$env:ProgramFiles\Google\Chrome\Application\chrome.exe","$env:ProgramFiles(x86)\Google\Chrome\Application\chrome.exe")
    if($paths | Where-Object{Test-Path $_}){return $true}
    $keys=@("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall","HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall")
    foreach($k in $keys){ $hit=Get-ChildItem $k -ErrorAction SilentlyContinue | ForEach-Object{ try{Get-ItemProperty $_.PSPath}catch{} } | Where-Object{ $_.DisplayName -like "Google Chrome*" }; if($hit){return $true} }
    return $false
  }
  if (Test-ChromeInstalled) { WriteLog "Chrome present; skip" }
  else {
    Try-Run {
      if (Get-Command winget -ErrorAction SilentlyContinue) {
        winget install --id Google.Chrome --silent --accept-source-agreements --accept-package-agreements | Out-Null
      } else { Write-Warning "winget not found; provide Chrome MSI locally." }
    } "Install Chrome"
  }

  # Optional: default browser (interactive on Win11)
  $DefaultAppXml = Join-Path $Here "DefaultAppAssociations.xml"
  if (Test-Path $DefaultAppXml) { Try-Run { Dism /Online /Import-DefaultAppAssociations:$DefaultAppXml | Out-Null } "Import default apps XML" }
  else { Try-Run { Start-Process "ms-settings:defaultapps?apiname=Microsoft.Chrome"; Start-Sleep 12 } "Open Default Apps (interactive)" }

  # CRD host
  Try-Run {
    $crdMsi = Get-Or-Download -LocalName "chromeremotedesktophost.msi" -Url $GDRIVE_CRD_MSI
    Start-Process msiexec.exe -ArgumentList "/i `"$crdMsi`" /qn /norestart" -Wait
  } "Install Chrome Remote Desktop Host"

  # .NET 3.5
  Try-Run { DISM /Online /Enable-Feature /FeatureName:NetFx3 /All /Quiet /NoRestart | Out-Null } ".NET 3.5"

  # Python
  Try-Run {
    $py = Get-Or-Download -LocalName "python_installer.exe" -Url $GDRIVE_PY_EXE
    if (Test-Path $py) {
      if ([IO.Path]::GetExtension($py).ToLower() -eq ".msi") {
        Start-Process msiexec.exe -ArgumentList "/i `"$py`" /qn /norestart" -Wait
      } else {
        $ok=$false
        foreach($sw in @('/quiet InstallAllUsers=1 PrependPath=1','/quiet','/passive','/S','/VERYSILENT','/silent')){
          try{ Start-Process $py -ArgumentList $sw -Wait -NoNewWindow -ErrorAction Stop; $ok=$true; break }catch{}
        }
        if(-not $ok){ Write-Warning "Python installer may need interactive run; check its silent flags." }
      }
    }
  } "Install Python (best-effort)"

  # Machine Expert Basic
  Try-Run {
    $zip = Get-Or-Download -LocalName "MachineExpertBasic_V1.2_SP1.zip" -Url $GDRIVE_MEB_ZIP
    $dst = Join-Path $Here "MachineExpertBasic_Extracted"
    if(Test-Path $dst){ Remove-Item $dst -Recurse -Force }
    Expand-Archive -Path $zip -DestinationPath $dst -Force
    $msi = Get-ChildItem $dst -Recurse -Filter *.msi -ErrorAction SilentlyContinue | Select-Object -First 1
    $exe = Get-ChildItem $dst -Recurse -Filter *.exe -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'setup|install|machine|expert' } | Select-Object -First 1
    if($msi){ Start-Process msiexec.exe -ArgumentList "/i `"$($msi.FullName)`" /qn /norestart" -Wait }
    elseif($exe){
      $ok=$false; foreach($sw in @('/S','/silent','/verysilent','/qn','/s')){ try{ Start-Process $exe.FullName -ArgumentList $sw -Wait -NoNewWindow; $ok=$true; break }catch{} }
      if(-not $ok){ Write-Warning "Machine Expert installer might need interactive run." }
    } else { throw "No installer found inside the Machine Expert ZIP." }
  } "Install Machine Expert Basic"

  # Power + background noise
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

  # Firewall for CRD
  Try-Run {
    $hostExe = "$env:ProgramFiles\Google\Chrome Remote Desktop\CurrentVersion\remoting_host.exe"
    if(Test-Path $hostExe){
      New-NetFirewallRule -DisplayName "Chrome Remote Desktop Inbound" -Direction Inbound -Program $hostExe -Action Allow -Protocol TCP -Profile Any -ErrorAction SilentlyContinue | Out-Null
      New-NetFirewallRule -DisplayName "Chrome Remote Desktop Outbound" -Direction Outbound -Program $hostExe -Action Allow -Protocol TCP -Profile Any -ErrorAction SilentlyContinue | Out-Null
    }
  } "Firewall rules for CRD"

  # Open CRD activation UI
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
