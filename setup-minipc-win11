<#
  setup-mini-pc.ps1
  Run as Administrator.

  What it does (summary)
  - Adds Defender exclusion for the folder the script lives in
  - Prompts you for computer name (optional) and renames machine (reboot required)
  - Downloads CRD MSI, Python EXE, MachineExpert ZIP from Google Drive links you provided
    (handles Drive's "large file" confirmation flow)
  - Installs Python (best-effort silent), CRD Host (msiexec /qn), and Machine Expert (silent best-effort)
  - Enables .NET 3.5 (DISM)
  - Sets display scale to 125% (requires sign-out/reboot)
  - Keeps the system awake, disables hibernate
  - Adds firewall rules for CRD host if present
  - Opens Chrome to remotedesktop.google.com/access for interactive CRD activation
  - Leaves Defender exclusions in place (optional cleanup commented out)
#>

# ---------- CONFIG: Google Drive share URLs you gave ----------
$GDRIVE_PY_EXE = "https://drive.google.com/file/d/1PANRP9dGXGla93-BdI3AfmnnDpKNblEG/view?usp=sharing"
$GDRIVE_MEB_ZIP = "https://drive.google.com/file/d/19qg1MpLobyjUdFDmXnJhhdSJrM8kZ41B/view?usp=sharing"
$GDRIVE_CRD_MSI = "https://drive.google.com/file/d/1G6IY2CRWAdnTLKcjStJGMQFELX85VEwI/view?usp=sharing"
# ---------------------------------------------------------------

$ErrorActionPreference = 'Stop'

# ---- Admin guard ----
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "Please run this script as Administrator." -ForegroundColor Yellow
  exit 1
}

# ---- Helpers & logging ----
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $Here) { $Here = $env:TEMP }   # fallback if run from pipeline
$Log = Join-Path $Here "setup-mini-pc.log"
"=== Run: $(Get-Date) on $env:COMPUTERNAME ===" | Out-File $Log -Append -Encoding utf8
function Log($m){ $m | Out-File $Log -Append }
function Try-Run($scriptBlock, $desc) {
  try { & $scriptBlock; Log "OK: $desc" }
  catch { Log "ERR: $desc :: $($_.Exception.Message)"; Write-Warning "Failed: $desc -> $($_.Exception.Message)" }
}

# ---- Google Drive downloader (handles confirm token for large files) ----
function Download-GoogleDrive {
  param(
    [string]$ShareUrl,
    [string]$DestinationPath
  )

  # Extract file id from many possible Drive URL formats
  $id = $null
  if ($ShareUrl -match '/d/([A-Za-z0-9_-]+)') { $id = $Matches[1] }
  elseif ($ShareUrl -match 'id=([A-Za-z0-9_-]+)') { $id = $Matches[1] }
  else { throw "Couldn't parse Google Drive file id from URL: $ShareUrl" }

  $baseUri = "https://docs.google.com/uc?export=download&id=$id"
  $wc = New-Object System.Net.Http.HttpClient
  $handler = New-Object System.Net.Http.HttpClientHandler
  $handler.AllowAutoRedirect = $true
  $client = New-Object System.Net.Http.HttpClient($handler)

  # first request - may return an HTML page with a confirmation token for large files
  $resp1 = $client.GetAsync($baseUri).Result
  $contentType = $resp1.Content.Headers.ContentType.MediaType
  $content = $resp1.Content.ReadAsStringAsync().Result

  # If response is the file (content-type != html), write it directly
  if ($contentType -ne "text/html") {
    [IO.File]::WriteAllBytes($DestinationPath, $resp1.Content.ReadAsByteArrayAsync().Result)
    return
  }

  # otherwise try to find confirm token in the HTML
  # look for confirm=TOKEN in any hrefs/inputs or the cookie name download_warning_{id}
  $token = $null
  if ($content -match 'confirm=([0-9A-Za-z_-]+)') { $token = $Matches[1] }
  elseif ($content -match 'name="confirm" value="([0-9A-Za-z_-]+)"') { $token = $Matches[1] }

  if (-not $token) {
    # try to read cookies; sometimes Google sends a download_warning cookie
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

  if (-not $token) {
    throw "Could not obtain Google Drive confirmation token. Manual download may be required."
  }

  # request again with confirm token
  $uri2 = "$baseUri&confirm=$token"
  $resp2 = $client.GetAsync($uri2).Result
  if ($resp2.IsSuccessStatusCode) {
    [IO.File]::WriteAllBytes($DestinationPath, $resp2.Content.ReadAsByteArrayAsync().Result)
  } else {
    throw "Download failed from Google Drive (status code $($resp2.StatusCode))."
  }
}

# ---- Download helper that understands local vs Drive vs http(s) ----
function Get-Or-Download {
  param([string]$LocalName, [string]$Url)
  $local = Join-Path $Here $LocalName
  if (Test-Path $local) { return $local }

  $dest = Join-Path $env:TEMP $LocalName

  if ($Url -like "*drive.google.com*") {
    Write-Host "Downloading from Google Drive: $LocalName ..."
    Download-GoogleDrive -ShareUrl $Url -DestinationPath $dest
    return $dest
  } else {
    Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $dest
    return $dest
  }
}

# ---- Defender exclusions for provisioning folder + powershell process ----
$ProvisionDir = $Here
Try-Run {
  Add-MpPreference -ExclusionPath $ProvisionDir -ErrorAction SilentlyContinue
  Add-MpPreference -ExclusionProcess "powershell.exe" -ErrorAction SilentlyContinue
  Write-Host "Added Defender exclusions for $ProvisionDir and powershell.exe" -ForegroundColor Cyan
} "Defender exclusions (provision folder + PowerShell)"

# ---- Prompt for computer name (optional) ----
$DesiredComputerName = Read-Host "Enter computer name (leave blank to keep current: $env:COMPUTERNAME)"
if ($DesiredComputerName -and $DesiredComputerName -ne $env:COMPUTERNAME) {
  Try-Run { Rename-Computer -NewName $DesiredComputerName -Force } "Rename computer to '$DesiredComputerName' (reboot required)"
}

# ---- Chrome detection (skip install if present) ----
function Test-ChromeInstalled {
  $candidates = @("$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
                  "$env:ProgramFiles(x86)\Google\Chrome\Application\chrome.exe")
  if ($candidates | Where-Object { Test-Path $_ }) { return $true }
  $keys = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall")
  foreach($k in $keys) {
    $hit = Get-ChildItem $k -ErrorAction SilentlyContinue | ForEach-Object {
      try { Get-ItemProperty $_.PSPath } catch { $null }
    } | Where-Object { $_.DisplayName -like "Google Chrome*" }
    if ($hit) { return $true }
  }
  return $false
}

if (Test-ChromeInstalled) {
  Write-Host "Chrome present — skipping install." -ForegroundColor Cyan
  Log "Skip: Chrome already installed"
} else {
  Try-Run {
    if (Get-Command winget -ErrorAction SilentlyContinue) {
      winget install --id Google.Chrome --silent --accept-source-agreements --accept-package-agreements | Out-Null
    } else {
      Write-Warning "winget not found; please install Chrome manually or provide an MSI in the script folder."
    }
  } "Install Google Chrome"
}

# ---- Best-effort: make Chrome default (interactive on Win11) ----
$DefaultAppXml = Join-Path $Here "DefaultAppAssociations.xml"
if (Test-Path $DefaultAppXml) {
  Try-Run { Dism /Online /Import-DefaultAppAssociations:$DefaultAppXml | Out-Null } "Import Default App Associations XML"
} else {
  Try-Run { Start-Process "ms-settings:defaultapps?apiname=Microsoft.Chrome"; Start-Sleep 20 } "Open Settings for 'Make default' (click manually)"
}

# ---- Download & install CRD MSI from your Drive link ----
Try-Run {
  $crdMsiPath = Get-Or-Download -LocalName "chromeremotedesktophost.msi" -Url $GDRIVE_CRD_MSI
  Start-Process msiexec.exe -ArgumentList "/i `"$crdMsiPath`" /qn /norestart" -Wait
} "Install Chrome Remote Desktop Host"

# ---- Enable .NET 3.5 (may be needed) ----
Try-Run { DISM /Online /Enable-Feature /FeatureName:NetFx3 /All /Quiet /NoRestart | Out-Null } ".NET Framework 3.5"

# ---- Download & install Python EXE (best-effort silent) ----
Try-Run {
  $pyExe = Get-Or-Download -LocalName "python_installer.exe" -Url $GDRIVE_PY_EXE
  if ($pyExe -and (Test-Path $pyExe)) {
    $ext = [IO.Path]::GetExtension($pyExe).ToLower()
    if ($ext -eq ".msi") {
      Start-Process msiexec.exe -ArgumentList "/i `"$pyExe`" /qn /norestart" -Wait
    } else {
      # Try common Python installer silent args (InstallAllUsers=1 PrependPath=1 /quiet)
      $tried = $false
      Try {
        Start-Process -FilePath $pyExe -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1" -Wait -ErrorAction Stop
        $tried = $true
      } catch {}
      if (-not $tried) {
        foreach ($sw in @('/quiet','/passive','/S','/VERYSILENT','/silent')) {
          try {
            Start-Process -FilePath $pyExe -ArgumentList $sw -Wait -ErrorAction Stop
            $tried = $true
            break
          } catch {}
        }
      }
      if (-not $tried) { Write-Warning "Python installer ran but we couldn't confirm silent install. You may need to run interactively." }
    }
  }
} "Install Python (best-effort silent)"

# ---- Download & install Machine Expert Basic ----
Try-Run {
  $mebZip = Get-Or-Download -LocalName "MachineExpertBasic_V1.2_SP1.zip" -Url $GDRIVE_MEB_ZIP
  $dst = Join-Path $Here "MachineExpertBasic_Extracted"
  if (Test-Path $dst) { Remove-Item $dst -Recurse -Force }
  Expand-Archive -Path $mebZip -DestinationPath $dst -Force
  $msi = Get-ChildItem $dst -Recurse -Filter *.msi -ErrorAction SilentlyContinue | Select-Object -First 1
  $exe = Get-ChildItem $dst -Recurse -Filter *.exe -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'setup|install|machine|expert' } | Select-Object -First 1
  if ($msi) {
    Start-Process msiexec.exe -ArgumentList "/i `"$($msi.FullName)`" /qn /norestart" -Wait
  } elseif ($exe) {
    $installed = $false
    foreach ($sw in @('/S','/silent','/verysilent','/qn','/s')) {
      try { Start-Process $exe.FullName -ArgumentList $sw -Wait -NoNewWindow; $installed = $true; break } catch {}
    }
    if (-not $installed) { Write-Warning "Couldn't run Machine Expert installer silently; try running interactively once to confirm flags." }
  } else { throw "No installer found inside the expanded Machine Expert ZIP." }
} "Install Machine Expert Basic"

# ---- Set display scale to 125% (DPI=120) for current user (needs sign-out/reboot) ----
Try-Run {
  New-Item -Path "HKCU:\Control Panel\Desktop" -Force | Out-Null
  Set-ItemProperty "HKCU:\Control Panel\Desktop" -Name "LogPixels" -Type DWord -Value 120
  Set-ItemProperty "HKCU:\Control Panel\Desktop" -Name "Win8DpiScaling" -Type DWord -Value 1
} "Set display scale to 125%"

# ---- Keep system awake / disable hibernate ----
Try-Run {
  powercfg /HIBERNATE OFF
  powercfg -Change -standby-timeout-ac 0
  powercfg -Change -monitor-timeout-ac 0
  powercfg -Change -disk-timeout-ac 0
  powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_VIDEO ADAPTBRIGHT 0
  powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_SLEEP HYBRIDSLEEP 0
  powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_SLEEP STANDBYIDLE 0
  powercfg -SetActive SCHEME_CURRENT
} "Keep system awake (AC)"

# ---- Reduce background noise (safe policies) ----
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

# ---- Firewall rules for CRD (if present) ----
Try-Run {
  $hostExe = "$env:ProgramFiles\Google\Chrome Remote Desktop\CurrentVersion\remoting_host.exe"
  if (Test-Path $hostExe) {
    New-NetFirewallRule -DisplayName "Chrome Remote Desktop Inbound" -Direction Inbound -Program $hostExe -Action Allow -Protocol TCP -Profile Any -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -DisplayName "Chrome Remote Desktop Outbound" -Direction Outbound -Program $hostExe -Action Allow -Protocol TCP -Profile Any -ErrorAction SilentlyContinue | Out-Null
  }
} "Firewall rules for CRD"

# ---- Launch CRD activation page (interactive 'Turn on') ----
Write-Host "`nOpening Chrome to Chrome Remote Desktop. Sign into Chrome as service@thetrivialcompany.com, click 'Turn on', confirm name, and set PIN (e.g., 748447)." -ForegroundColor Green
Try-Run { Start-Process "chrome.exe" "https://remotedesktop.google.com/access" } "Open CRD activation page"

Write-Host "`nAll steps attempted. Reboot to apply rename/DPI changes." -ForegroundColor Green
Log "Done: $(Get-Date)"

 ---- OPTIONAL cleanup: remove Defender exclusions (uncomment to enable) ----
 Try-Run {
   Remove-MpPreference -ExclusionPath $ProvisionDir -ErrorAction SilentlyContinue
   Remove-MpPreference -ExclusionProcess "powershell.exe" -ErrorAction SilentlyContinue
   Write-Host "Removed Defender exclusions." -ForegroundColor Green
 } "Cleanup Defender exclusions"
