<#
  setup-minipc-win11.ps1 — RUN AS ADMIN (PowerShell 5.1)
  Menu-driven provisioning for your mini-PCs.
  Choose only what you want each run (installs, PLC NIC, updates hardening, etc).
#>

param([switch]$Resume)

# ====== LINKS & FALLBACKS ======
$GDRIVE_PY_EXE      = "https://drive.google.com/file/d/1PANRP9dGXGla93-BdI3AfmnnDpKNblEG/view?usp=sharing"
$GDRIVE_MEB_EXE     = "https://drive.google.com/file/d/1CfLdcXN1DqRZDGCWsPxpo3XFS7kbmMrN/view?usp=sharing"
$GDRIVE_CRD_MSI     = "https://drive.google.com/file/d/1G6IY2CRWAdnTLKcjStJGMQFELX85VEwI/view?usp=sharing"
$GDRIVE_FOLDER_ROOT = "https://drive.google.com/drive/folders/1FuLqB892C_6ktjGnyV-X4qPQqeDr0-D8?usp=drive_link"

$FALLBACK_CHROME_MSI = "https://dl.google.com/chrome/install/GoogleChromeStandaloneEnterprise64.msi"
$FALLBACK_CRD_MSI    = "https://dl.google.com/edgedl/chrome-remote-desktop/chromeremotedesktophost.msi"
$FALLBACK_PY_EXE     = "https://www.python.org/ftp/python/3.12.6/python-3.12.6-amd64.exe"

# ====== SETUP & LOG ======
$TaskName = "ProvisionMiniPC_AutoResume"
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path; if (-not $Here) { $Here = $env:TEMP }
$Log  = Join-Path $Here "setup-mini-pc.log"
"=== Run: $(Get-Date) on $env:COMPUTERNAME (Resume=$Resume) ===" | Out-File $Log -Append -Encoding utf8

function WriteLog($m){ $m | Out-File -FilePath $Log -Append -Encoding utf8; Write-Host $m }
$Global:ChangeReport = @()
function Report($msg){ $Global:ChangeReport += $msg; WriteLog $msg }

# ====== ADMIN CHECK ======
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){ Write-Error "Run this script as Administrator."; exit 1 }

# ====== HELPERS (network, download, etc.) ======
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
  $base="https://docs.google.com/uc?export=download&id=$id"
  if(Test-Path $DestinationPath){ Remove-Item $DestinationPath -Force -ErrorAction SilentlyContinue }
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
    Invoke-WebRequest -UseBasicParsing -Uri "$base&confirm=$token" -WebSession $sess -OutFile $DestinationPath -Headers $headers -TimeoutSec $TimeoutSec
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
function Try-Run($sb,$desc){ try{ & $sb; Report "OK: $desc" } catch{ WriteLog ("ERR: {0} :: {1}" -f $desc,$_.Exception.Message); Write-Warning "Failed: $desc -> $($_.Exception.Message)"; $Global:ChangeReport += "FAILED: $desc ($($_.Exception.Message))" } }

# ====== APPS/FEATURE DETECTION ======
function Test-ChromeInstalled {
  $paths=@("$env:ProgramFiles\Google\Chrome\Application\chrome.exe","$env:ProgramFiles(x86)\Google\Chrome\Application\chrome.exe")
  if($paths | Where-Object{Test-Path $_}){return $true}
  $keys=@("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall","HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall")
  foreach($k in $keys){ $hit=Get-ChildItem $k -ErrorAction SilentlyContinue | ForEach-Object{ try{Get-ItemProperty $_.PSPath}catch{} } | Where-Object{ $_.DisplayName -like "Google Chrome*" }; if($hit){return $true} }
  return $false
}

# ====== RESUME TASK (for reboot after rename/DPI) ======
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

# ====== UX / FONT ======
function Ensure-ClearType {
  New-Item -Path "HKCU:\Control Panel\Desktop" -Force | Out-Null
  Set-ItemProperty "HKCU:\Control Panel\Desktop" -Name "FontSmoothing" -Type String -Value "2"
  Set-ItemProperty "HKCU:\Control Panel\Desktop" -Name "FontSmoothingType" -Type DWord -Value 2
  rundll32.exe user32.dll,UpdatePerUserSystemParameters
  Report "Fonts set to ClearType (anti-aliased)."
}

# ====== PLC NIC ======
function Get-DefaultRouteIfIndex {
  (Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
    Sort-Object -Property RouteMetric,Publish -Descending:$false |
    Select-Object -First 1).ifIndex
}
function Get-PLCSuffix {
  $m = [regex]::Match($env:COMPUTERNAME, '([A-Za-z])(?!.*[A-Za-z])')
  if ($m.Success) { $m.Groups[1].Value.ToUpper() } else { 'A' }
}
function Set-PLCAdapter {
  param([string]$IPAddress="192.168.1.100",[int]$Prefix=24)
  $defaultIf = Get-DefaultRouteIfIndex
  $candidates = Get-NetAdapter -Physical | Where-Object {
      $_.Status -eq "Up" -and $_.HardwareInterface -and $_.MediaType -in 802.3,"Ethernet" -and
      $_.ifIndex -ne $defaultIf -and $_.Name -notmatch 'vEthernet|Bluetooth|Wi-?Fi'
  }
  if (-not $candidates) { throw "No PLC NIC candidate found (is the second NIC connected/powered?)." }
  $nic = $candidates | Where-Object { $_.InterfaceDescription -match "Realtek.*USB" } | Select-Object -First 1
  if (-not $nic) { $nic = $candidates | Select-Object -First 1 }
  $alias = "PLC$(Get-PLCSuffix)"
  if ($nic.Name -ne $alias) { Rename-NetAdapter -Name $nic.Name -NewName $alias -PassThru | Out-Null }
  Set-NetIPInterface -InterfaceAlias $alias -Dhcp Disabled -AddressFamily IPv4 -ErrorAction SilentlyContinue
  Get-NetIPAddress -InterfaceAlias $alias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -ne $IPAddress } | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
  if (-not (Get-NetIPAddress -InterfaceAlias $alias -AddressFamily IPv4 | Where-Object { $_.IPAddress -eq $IPAddress })) {
    New-NetIPAddress -InterfaceAlias $alias -IPAddress $IPAddress -PrefixLength $Prefix -ErrorAction Stop | Out-Null
  }
  Set-NetConnectionProfile -InterfaceAlias $alias -NetworkCategory Private -ErrorAction SilentlyContinue
  Disable-NetAdapterBinding -Name $alias -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
  Set-DnsClientServerAddress -InterfaceAlias $alias -ResetServerAddresses
  Report "PLC NIC '$alias' set to $IPAddress/$Prefix (no gateway, DNS empty)."
}

# ====== EDGE SUPPRESSION & CHROME PIN (SHELL VERBS) ======
function Invoke-ShellVerb { param([string]$Path,[string]$VerbMatch)
  if (-not (Test-Path $Path)) { return $false }
  $folder = Split-Path $Path; $file = Split-Path $Path -Leaf
  $shell  = New-Object -ComObject Shell.Application
  $item   = $shell.Namespace($folder).ParseName($file)
  if (-not $item) { return $false }
  foreach ($v in $item.Verbs()) { $name = ($v.Name -replace '&','').Trim(); if ($name -like "*$VerbMatch*") { $v.DoIt(); return $true } }
  return $false
}
function Refresh-Explorer { Get-Process explorer -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue; Start-Process explorer.exe }
function Hide-Edge-And-Pin-Chrome {
  New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Force | Out-Null
  Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "HideFirstRunExperience" -Type DWord -Value 1
  Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "CreateDesktopShortcutDefault" -Type DWord -Value 0
  reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "DisableEdgeDesktopShortcutCreation" /t REG_DWORD /d 1 /f | Out-Null
  $edge = "$env:ProgramFiles (x86)\Microsoft\Edge\Application\msedge.exe"; if (-not (Test-Path $edge)) { $edge = "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe" }
  $chrome = "$env:ProgramFiles\Google\Chrome\Application\chrome.exe"; if (-not (Test-Path $chrome)) { $chrome = "$env:ProgramFiles(x86)\Google\Chrome\Application\chrome.exe" }
  $u1 = Invoke-ShellVerb -Path $edge   -VerbMatch "Unpin from taskbar"; Start-Sleep 1
  $p1 = Invoke-ShellVerb -Path $chrome -VerbMatch "Pin to taskbar";      Start-Sleep 1
  Refresh-Explorer; Start-Sleep 2
  $u2 = Invoke-ShellVerb -Path $edge   -VerbMatch "Unpin from taskbar"
  $p2 = Invoke-ShellVerb -Path $chrome -VerbMatch "Pin to taskbar"
  Refresh-Explorer
  if ($u1 -or $u2) { Report "Edge unpinned from taskbar." } else { $Global:ChangeReport += "NOTE: Edge might already be unpinned (verb missing)." }
  if ($p1 -or $p2) { Report "Chrome pinned to taskbar." } else { $Global:ChangeReport += "FAILED: Could not pin Chrome (verb not found?)." }
}

# ====== ACTIONS (callable by menu) ======
function Act-RenameAndDPI {
  $DesiredComputerName = Read-Host "Enter computer name (blank keeps $env:COMPUTERNAME)"
  $needReboot=$false
  if ($DesiredComputerName -and $DesiredComputerName -ne $env:COMPUTERNAME) { Try-Run { Rename-Computer -NewName $DesiredComputerName -Force } "Rename to $DesiredComputerName"; $needReboot=$true }
  $wantDPI = Read-Host "Set display scaling to 125%? (Y/N, default N)"
  if ($wantDPI -match '^[Yy]'){ Try-Run { New-Item "HKCU:\Control Panel\Desktop" -Force | Out-Null; Set-ItemProperty "HKCU:\Control Panel\Desktop" -Name "LogPixels" -Type DWord -Value 120; Set-ItemProperty "HKCU:\Control Panel\Desktop" -Name "Win8DpiScaling" -Type DWord -Value 1 } "Set DPI to 125%"; $needReboot=$true }
  else { Try-Run { New-Item "HKCU:\Control Panel\Desktop" -Force | Out-Null; Set-ItemProperty "HKCU:\Control Panel\Desktop" -Name "Win8DpiScaling" -Type DWord -Value 0; Remove-ItemProperty "HKCU:\Control Panel\Desktop" -Name "LogPixels" -ErrorAction SilentlyContinue } "Ensure DPI 100% (no scaling)" }
  Try-Run { Ensure-ClearType } "Enable ClearType (font smoothing)"
  if ($needReboot){
    $scriptPath = if ($PSCommandPath) { $PSCommandPath } else { $MyInvocation.MyCommand.Path }
    Try-Run { Create-ResumeTask -ScriptPath $scriptPath } "Create resume task"
    Write-Host "Rebooting to apply changes… (script will auto-resume)" -ForegroundColor Yellow
    Restart-Computer -Force
  }
}

function Act-InstallChrome {
  if (Test-ChromeInstalled) { Report "Chrome already installed." }
  else {
    if (Get-Command winget -ErrorAction SilentlyContinue) { Try-Run { winget install --id Google.Chrome --silent --accept-source-agreements --accept-package-agreements | Out-Null } "Install Chrome (winget)" }
    else { Try-Run { $chrome = Get-FromSources -LocalName "GoogleChromeStandaloneEnterprise64.msi" -Sources @($FALLBACK_CHROME_MSI); Start-Process msiexec.exe -ArgumentList "/i `"$chrome`" /qn /norestart" -Wait } "Install Chrome (MSI)" }
  }
}

function Act-InstallCRD {
  Try-Run {
    $crdLocal = $null
    try { $crdLocal = Get-FromSources -LocalName "chromeremotedesktophost.msi" -Sources @($GDRIVE_CRD_MSI, $FALLBACK_CRD_MSI) } catch {}
    if (-not $crdLocal) {
      $target = Join-Path $env:USERPROFILE 'Downloads\chromeremotedesktophost.msi'
      [void](Open-ManualAndWait -UrlPrimary $FALLBACK_CRD_MSI -UrlAlsoOpen $GDRIVE_FOLDER_ROOT -Message "Download CRD Host and save as: $target . Script continues when it appears." -TargetPath $target)
      if (Test-Path $target) { $crdLocal = $target }
    }
    if ($crdLocal) { Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$crdLocal`" /qn /norestart" -Wait -NoNewWindow }
    $hostExe = "$env:ProgramFiles\Google\Chrome Remote Desktop\CurrentVersion\remoting_host.exe"
    if (Test-Path $hostExe) { Report "CRD Host installed." } else { $Global:ChangeReport += "ACTION NEEDED: Finish CRD host install in browser."; Start-Process "chrome.exe" "--new-window https://remotedesktop.google.com/access" | Out-Null }
  } "Install Chrome Remote Desktop Host"
}

function Act-InstallPython {
  function Test-Python { (Get-Command python -ErrorAction SilentlyContinue) -or (Get-Command py -ErrorAction SilentlyContinue) }
  if (Test-Python) { Report "Python already present." }
  else {
    Try-Run {
      $py = $null
      try { $py = Get-FromSources -LocalName "python_installer.exe" -Sources @($GDRIVE_PY_EXE, $FALLBACK_PY_EXE) } catch {}
      if (-not $py) { [void](Open-ManualAndWait -UrlPrimary "https://www.python.org/downloads/windows/" -Message "Download Python 3.x (64-bit) and run it. Press ENTER here when done.") }
      else { Start-Process -FilePath $py -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1 Include_test=0" -Wait -NoNewWindow }
      if (Test-Python) { Report "Python installed and in PATH." } else { $Global:ChangeReport += "FAILED: Python not detected after attempt." }
    } "Install Python"
  }
}

function Act-InstallMEB {
  Try-Run {
    function Test-MEBFile([string]$p){ if (-not (Test-Path $p)) { return $false }; ((Get-Item $p).Length -ge 450MB) -and (Test-InstallerMagic $p) }
    $meb = $null
    try { $meb = Get-FromSources -LocalName "MachineExpertBasic_Setup.exe" -Sources @($GDRIVE_MEB_EXE) -MinBytes 450MB } catch {}
    if (-not $meb) {
      foreach($c in @((Join-Path $env:USERPROFILE 'Downloads\MachineExpertBasic_Setup.exe'), (Join-Path $env:USERPROFILE 'Downloads\MachineExpertBasic_Setup'), (Join-Path $env:USERPROFILE 'Desktop\MachineExpertBasic_Setup.exe'))){ if (Test-MEBFile $c){ $meb=$c; break } }
    }
    if (-not $meb) {
      $target = Join-Path $env:USERPROFILE 'Downloads\MachineExpertBasic_Setup.exe'
      [void](Open-ManualAndWait -UrlPrimary $GDRIVE_MEB_EXE -UrlAlsoOpen $GDRIVE_FOLDER_ROOT -Message "Download from Drive and save as: $target . Script continues when it appears." -TargetPath $target)
      if (Test-MEBFile $target){ $meb=$target }
    }
    if (-not $meb){ throw "Machine Expert EXE not available" }
    $ok=$false; foreach($sw in @('/S','/silent','/verysilent','/qn','/quiet','/s','/passive')){ try{ Start-Process -FilePath $meb -ArgumentList $sw -Wait -NoNewWindow -ErrorAction Stop; $ok=$true; break }catch{} }
    if (-not $ok){ Start-Process -FilePath $meb -Wait }
    Report "Machine Expert Basic installed (or launched for manual install)."
  } "Install Machine Expert Basic"
}

function Act-PowerAlwaysOn {
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
}

function Act-DisableWindowsUpdate {
  Try-Run {
    New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Force | Out-Null
    New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
    Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Type DWord -Value 1
    Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Type DWord -Value 2
    Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -Type DWord -Value 1
    New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
    Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1
    Try{ Stop-Service WSearch -Force }Catch{}
    Set-Service WSearch -StartupType Disabled
    foreach($svcName in @("wuauserv","UsoSvc","BITS","DoSvc","WaaSMedicSvc")){
      $svc=Get-Service -Name $svcName -ErrorAction SilentlyContinue
      if($svc){ try{ Stop-Service $svc -Force -ErrorAction SilentlyContinue }catch{}; try{ Set-Service $svc -StartupType Disabled }catch{} }
    }
    $taskPaths=@("\Microsoft\Windows\WindowsUpdate\","\Microsoft\Windows\UpdateOrchestrator\","\Microsoft\Windows\WaaSMedic\")
    foreach($tp in $taskPaths){ $tasks=Get-ScheduledTask -TaskPath $tp -ErrorAction SilentlyContinue; foreach($t in $tasks){ try{ Disable-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction SilentlyContinue }catch{} } }
  } "Halt Windows Update (services + policies + tasks)"
}

function Act-DisableOneDrive {
  Try-Run {
    $envSys = "$env:SystemRoot\System32\OneDriveSetup.exe"
    $envWow = "$env:SystemRoot\SysWOW64\OneDriveSetup.exe"
    Get-Process OneDrive -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    if (Test-Path $envSys) { & $envSys /uninstall | Out-Null }
    if (Test-Path $envWow) { & $envWow /uninstall | Out-Null }
    New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Force | Out-Null
    Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSync" -Type DWord -Value 1
    Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1
    foreach($rk in @("HKCU:\Software\Microsoft\Windows\CurrentVersion\Run","HKLM:\Software\Microsoft\Windows\CurrentVersion\Run")){
      if (Test-Path $rk) { if (Get-ItemProperty -Path $rk -Name OneDrive -ErrorAction SilentlyContinue) { Remove-ItemProperty -Path $rk -Name OneDrive -ErrorAction SilentlyContinue } }
    }
    Get-ScheduledTask -TaskName "*OneDrive*" -ErrorAction SilentlyContinue | Disable-ScheduledTask -ErrorAction SilentlyContinue | Out-Null
    Remove-Item "$env:UserProfile\OneDrive" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "$env:LocalAppData\Microsoft\OneDrive" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item "$env:ProgramData\Microsoft OneDrive" -Recurse -Force -ErrorAction SilentlyContinue
  } "OneDrive removed and disabled"
}

function Act-EdgeOffChromeOn { Try-Run { Hide-Edge-And-Pin-Chrome } "Taskbar: pin Chrome, unpin Edge" }
function Act-OpenDefaultApps { Try-Run { Start-Process "ms-settings:defaultapps?apiname=Microsoft.Chrome" -WindowStyle Minimized } "Open Default Apps settings" }
function Act-ChromeSignIn    { Try-Run { Start-Process "chrome.exe" "--new-window https://accounts.google.com/ServiceLogin"; Read-Host "Sign into Chrome, then press ENTER here" } "Chrome account sign-in prompt" }
function Act-PLCSetup        { $ip = Read-Host "PLC IPv4 (default 192.168.1.100)"; if([string]::IsNullOrWhiteSpace($ip)){$ip="192.168.1.100"}; Try-Run { Set-PLCAdapter -IPAddress $ip -Prefix 24 } "Configure PLC NIC" }
function Act-CRDFirewall     { Try-Run { $exe="$env:ProgramFiles\Google\Chrome Remote Desktop\CurrentVersion\remoting_host.exe"; if(Test-Path $exe){ New-NetFirewallRule -DisplayName "CRD Inbound" -Direction Inbound -Program $exe -Action Allow -Protocol TCP -Profile Any -ErrorAction SilentlyContinue | Out-Null; New-NetFirewallRule -DisplayName "CRD Outbound" -Direction Outbound -Program $exe -Action Allow -Protocol TCP -Profile Any -ErrorAction SilentlyContinue | Out-Null }; Start-Process "chrome.exe" "https://remotedesktop.google.com/access" | Out-Null } "CRD firewall + access page" }

# ====== MENU ======
$menuItems = @(
  @{k='1'; t='Rename computer / DPI / ClearType';          f={ Act-RenameAndDPI } }
  @{k='2'; t='Install Chrome';                             f={ Act-InstallChrome } }
  @{k='3'; t='Install Chrome Remote Desktop Host';         f={ Act-InstallCRD } }
  @{k='4'; t='Install Python (3.x)';                       f={ Act-InstallPython } }
  @{k='5'; t='Install Machine Expert Basic';               f={ Act-InstallMEB } }
  @{k='6'; t='Power: keep system always on';               f={ Act-PowerAlwaysOn } }
  @{k='7'; t='Disable Windows Update (services+tasks)';    f={ Act-DisableWindowsUpdate } }
  @{k='8'; t='Remove/disable OneDrive';                    f={ Act-DisableOneDrive } }
  @{k='9'; t='Taskbar: unpin Edge + pin Chrome';           f={ Act-EdgeOffChromeOn } }
  @{k='A'; t='Open Default Apps page (set Chrome)';        f={ Act-OpenDefaultApps } }
  @{k='B'; t='Prompt Chrome sign-in';                      f={ Act-ChromeSignIn } }
  @{k='C'; t='Configure PLC NIC (rename + static IP)';     f={ Act-PLCSetup } }
  @{k='D'; t='CRD firewall + open access page';            f={ Act-CRDFirewall } }
  @{k='Z'; t='Run a sensible minimal profile (6,7,8,9,C)'; f={
        Act-PowerAlwaysOn; Act-DisableWindowsUpdate; Act-DisableOneDrive; Act-EdgeOffChromeOn; Act-PLCSetup
     } }
  @{k='Y'; t='Run full provisioning (2→5,6,7,8,9,C,D)';    f={
        Act-InstallChrome; Act-InstallCRD; Act-InstallPython; Act-InstallMEB;
        Act-PowerAlwaysOn; Act-DisableWindowsUpdate; Act-DisableOneDrive; Act-EdgeOffChromeOn; Act-PLCSetup; Act-CRDFirewall
     } }
)

function Show-Menu {
  Clear-Host
  Write-Host "========== TTC MINI-PC PROVISIONER ==========" -ForegroundColor Cyan
  Write-Host "Host: $env:COMPUTERNAME   User: $env:USERNAME" -ForegroundColor DarkGray
  Write-Host "Choose one or more options separated by commas (e.g., 2,3,9,C)."
  foreach($m in $menuItems){ Write-Host (" {0,-3} {1}" -f $m.k, $m.t) }
  Write-Host (" {0,-3} {1}" -f 'Q', 'Quit (show report)')
  Write-Host "---------------------------------------------"
}

# ====== MAIN LOOP ======
if (-not (Wait-Network -TimeoutSec 60)) { Write-Warning "Network not ready; continuing (some actions may prompt)." }

$continue=$true
while($continue){
  Show-Menu
  $ans = Read-Host "Selection"
  if ([string]::IsNullOrWhiteSpace($ans)) { continue }
  if ($ans.Trim().ToUpper() -eq 'Q') { break }
  $keys = $ans.Split(',') | ForEach-Object { $_.Trim().ToUpper() } | Where-Object { $_ }
  foreach($k in $keys){
    $item = $menuItems | Where-Object { $_.k -eq $k }
    if ($item){ & $item.f } else { Write-Host "Unknown option: $k" -ForegroundColor Yellow }
  }
  Read-Host "Press ENTER to return to menu (or type Q to finish)" | ForEach-Object {
    if ($_ -and $_.Trim().ToUpper() -eq 'Q'){ $continue=$false }
  }
}

# ====== FINAL SUMMARY ======
WriteLog "=== SESSION COMPLETE ==="
Write-Host "`n=====================================" -ForegroundColor Cyan
Write-Host "   MINI-PC PROVISIONING — SUMMARY" -ForegroundColor Green
Write-Host "=====================================" -ForegroundColor Cyan
$Global:ChangeReport | ForEach-Object { Write-Host " - $_" -ForegroundColor White }
Write-Host "`nDetailed log: $Log" -ForegroundColor DarkGray
Write-Host "Finished on $(Get-Date)." -ForegroundColor Green
