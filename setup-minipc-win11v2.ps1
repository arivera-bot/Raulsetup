<#
Install-RAUL-Full-Setup.ps1

Run as Administrator on Windows 10 or Windows 11:
  powershell -NoProfile -ExecutionPolicy Bypass -File .\Install-RAUL-Full-Setup.ps1

This combined script:
  - Prompts for supporting software:
      Chrome
      Chrome Remote Desktop Host
      Twido Suite
      Schneider Machine Expert Basic
      Python
  - Sets the PC up for remote/always-on use:
      keeps system awake
      opens Chrome Remote Desktop setup
      adds Chrome Remote Desktop firewall rules
      optionally renames the computer
      optionally sets display scaling to 125%
      enables ClearType
      disables OneDrive
      reduces Edge prompts/shortcuts
      optionally configures the PLC Ethernet adapter
  - Downloads and unzips RAUL 2.0
  - Updates RAULDASH and RAULMANUAL settings
  - Updates RAULMANUAL raul_config tab_name
  - Installs RAULDASH Python requirements and Flask
  - Creates a Windows startup BAT file that starts both RAUL apps
#>

param([switch]$Resume)

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ==================== LINKS ====================
$GDRIVE_RAUL_ZIP    = "https://drive.google.com/file/d/1EYRUZByBWuTKHPfY0sN6Lw_IQgSYTmu_/view?usp=sharing"
$GDRIVE_PY_EXE      = "https://drive.google.com/file/d/1PANRP9dGXGla93-BdI3AfmnnDpKNblEG/view?usp=sharing"
$GDRIVE_MEB_EXE     = "https://drive.google.com/file/d/1_-YOGugROM57rIpOz0ODy8EBL8AuR0X-/view?usp=sharing"
$GDRIVE_CRD_MSI     = "https://drive.google.com/file/d/1G6IY2CRWAdnTLKcjStJGMQFELX85VEwI/view?usp=sharing"
$GDRIVE_TWIDO_ZIP   = "https://drive.google.com/file/d/1PnXn2OLx4FmYFxn7qAgNHrVZoi5FlVeC/view?usp=sharing"
$GDRIVE_FOLDER_ROOT = "https://drive.google.com/drive/folders/1FuLqB892C_6ktjGnyV-X4qPQqeDr0-D8?usp=drive_link"

$FALLBACK_CHROME_MSI = "https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi"
$FALLBACK_CRD_MSI    = "https://dl.google.com/edgedl/chrome-remote-desktop/chromeremotedesktophost.msi"
$FALLBACK_PY_EXE     = "https://www.python.org/ftp/python/3.12.6/python-3.12.6-amd64.exe"

# ==================== PATHS ====================
$StableDir = "C:\ProgramData\Trivial"
$WorkDir = Join-Path $StableDir "RAULInstaller"
$Log = Join-Path $StableDir "raul-full-setup.log"
$InstallRoot = Join-Path $env:USERPROFILE "Downloads\RAUL 2.0"
$StartupBatName = "Start_RAUL_Apps.bat"

New-Item -ItemType Directory -Path $StableDir -Force | Out-Null
New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null

"=== Run: $(Get-Date) on $env:COMPUTERNAME ===" | Out-File $Log -Append -Encoding utf8 -Force

function WriteLog {
    param([string]$Message)

    $line = "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
    Write-Host $line
    $line | Out-File -FilePath $Log -Append -Encoding utf8 -Force
}

function Report {
    param([string]$Message)

    $Global:ChangeReport += $Message
    WriteLog $Message
}

$Global:ChangeReport = @()

function Assert-Admin {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this script as Administrator."
    }
}

function Prompt-YesNo {
    param(
        [Parameter(Mandatory=$true)][string]$Question,
        [bool]$DefaultYes = $true
    )

    $defaultText = if ($DefaultYes) { "Y" } else { "N" }

    while ($true) {
        $answer = (Read-Host "$Question (Y/N, default $defaultText)").Trim()
        if ([string]::IsNullOrWhiteSpace($answer)) { return $DefaultYes }
        if ($answer -match "^[Yy]") { return $true }
        if ($answer -match "^[Nn]") { return $false }
    }
}

function Try-Run {
    param(
        [scriptblock]$ScriptBlock,
        [string]$Description
    )

    try {
        & $ScriptBlock
        Report "OK: $Description"
    }
    catch {
        WriteLog "ERR: $Description :: $($_.Exception.Message)"
        Write-Warning "Failed: $Description -> $($_.Exception.Message)"
        $Global:ChangeReport += "FAILED: $Description ($($_.Exception.Message))"
    }
}

function Wait-Network {
    param([int]$TimeoutSec = 120)

    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $TimeoutSec) {
        try {
            [void][System.Net.Dns]::GetHostEntry("www.google.com")
            WriteLog "Network ready"
            return $true
        }
        catch {
            Start-Sleep 3
        }
    }

    WriteLog "Network not ready after $TimeoutSec seconds"
    return $false
}

function Test-NotHtml {
    param([string]$Path)

    if (-not (Test-Path $Path)) { return $false }

    try {
        $bytes = [IO.File]::ReadAllBytes($Path)
        if ($bytes.Length -lt 32) { return $false }
        $sliceLen = [Math]::Min(2048, $bytes.Length)
        $text = [Text.Encoding]::ASCII.GetString($bytes, 0, $sliceLen)
        if ($text -match "<!DOCTYPE\s+html" -or $text -match "<html" -or $text -match "Google Drive" -or $text -match "quota exceeded" -or $text -match "Sign in") {
            return $false
        }
        return $true
    }
    catch {
        return $false
    }
}

function Test-InstallerMagic {
    param([string]$Path)

    if (-not (Test-Path $Path)) { return $false }

    try {
        $stream = [IO.File]::Open($Path, "Open", "Read", "Read")
        $reader = New-Object IO.BinaryReader($stream)
        $bytes = $reader.ReadBytes(8)
        $reader.Close()
        $stream.Close()

        if ($bytes.Length -lt 2) { return $false }
        if ($bytes[0] -eq 0x4D -and $bytes[1] -eq 0x5A) { return $true }
        if ($bytes.Length -ge 8 -and $bytes[0] -eq 0xD0 -and $bytes[1] -eq 0xCF -and $bytes[2] -eq 0x11 -and $bytes[3] -eq 0xE0) { return $true }
        return $false
    }
    catch {
        return $false
    }
}

function Test-ZipMagic {
    param([string]$Path)

    if (-not (Test-Path $Path)) { return $false }

    try {
        $stream = [IO.File]::Open($Path, "Open", "Read", "Read")
        $reader = New-Object IO.BinaryReader($stream)
        $bytes = $reader.ReadBytes(4)
        $reader.Close()
        $stream.Close()
        return ($bytes.Length -ge 2 -and $bytes[0] -eq 0x50 -and $bytes[1] -eq 0x4B)
    }
    catch {
        return $false
    }
}

function Get-GoogleDriveFileId {
    param([string]$Url)

    if ($Url -match "/d/([A-Za-z0-9_-]+)") { return $Matches[1] }
    if ($Url -match "id=([A-Za-z0-9_-]+)") { return $Matches[1] }
    throw "Bad Google Drive URL: $Url"
}

function Download-GoogleDriveFile {
    param(
        [string]$ShareUrl,
        [string]$DestinationPath,
        [int64]$MinBytes = 1MB,
        [ValidateSet("Installer","Zip","Any")][string]$Kind = "Any"
    )

    $fileId = Get-GoogleDriveFileId -Url $ShareUrl
    $baseUrl = "https://docs.google.com/uc?export=download&id=$fileId"
    $headers = @{
        "User-Agent" = "Mozilla/5.0"
        "Accept" = "*/*"
    }

    if (Test-Path $DestinationPath) {
        Remove-Item $DestinationPath -Force -ErrorAction SilentlyContinue
    }

    WriteLog "Downloading from Google Drive: $fileId"

    $session = $null
    $response = Invoke-WebRequest -UseBasicParsing -Uri $baseUrl -Headers $headers -SessionVariable session -TimeoutSec 3600
    $confirmToken = $null

    foreach ($cookie in $session.Cookies.GetCookies([Uri]$baseUrl)) {
        if ($cookie.Name -like "download_warning*") {
            $confirmToken = $cookie.Value
            break
        }
    }

    if (-not $confirmToken) {
        if ($response.Content -match "confirm=([0-9A-Za-z_-]+)") {
            $confirmToken = $Matches[1]
        }
        elseif ($response.Content -match 'name="confirm"\s+value="([0-9A-Za-z_-]+)"') {            $confirmToken = $Matches[1]
        }
        elseif ($response.Content -match 'href="[^"]*?confirm=([0-9A-Za-z_-]+)[^"]*"') {
            $confirmToken = $Matches[1]
        }
    }

    if ($confirmToken) {
        $downloadUrl = "$baseUrl&confirm=$confirmToken"
        Invoke-WebRequest -UseBasicParsing -Uri $downloadUrl -WebSession $session -Headers $headers -OutFile $DestinationPath -TimeoutSec 3600
    }
    else {
        Invoke-WebRequest -UseBasicParsing -Uri $baseUrl -WebSession $session -Headers $headers -OutFile $DestinationPath -TimeoutSec 3600
    }

    if (-not (Test-Path $DestinationPath)) { throw "Download failed. File was not created." }
    if ((Get-Item $DestinationPath).Length -lt $MinBytes) { throw "Download is too small: $DestinationPath" }
    if (-not (Test-NotHtml $DestinationPath)) { throw "Downloaded an HTML page instead of a file. Check Drive permissions." }

    if ($Kind -eq "Installer" -and -not (Test-InstallerMagic $DestinationPath)) { throw "Downloaded file is not a valid EXE/MSI." }
    if ($Kind -eq "Zip" -and -not (Test-ZipMagic $DestinationPath)) { throw "Downloaded file is not a valid ZIP." }

    WriteLog "Downloaded to $DestinationPath"
    return $DestinationPath
}

function Invoke-WebRequest-Retry {
    param(
        [string]$Uri,
        [string]$OutFile,
        [int]$Retries = 4,
        [int]$DelaySec = 8
    )

    for ($i = 1; $i -le $Retries; $i++) {
        try {
            if (Test-Path $OutFile) { Remove-Item $OutFile -Force -ErrorAction SilentlyContinue }
            Invoke-WebRequest -UseBasicParsing -Uri $Uri -OutFile $OutFile -TimeoutSec 3600
            if ((Test-Path $OutFile) -and ((Get-Item $OutFile).Length -gt 1MB)) { return $OutFile }
            throw "Downloaded file missing or too small"
        }
        catch {
            WriteLog "Attempt $i/$Retries failed: $($_.Exception.Message)"
            if ($i -eq $Retries) { throw }
            Start-Sleep $DelaySec
        }
    }
}

function Get-FromSources {
    param(
        [string]$LocalName,
        [string[]]$Sources,
        [int64]$MinBytes = 1MB,
        [ValidateSet("Installer","Zip")][string]$Kind = "Installer"
    )

    $local = Join-Path $WorkDir $LocalName

    if (Test-Path $local -and (Get-Item $local).Length -ge $MinBytes -and (Test-NotHtml $local)) {
        if (($Kind -eq "Installer" -and (Test-InstallerMagic $local)) -or ($Kind -eq "Zip" -and (Test-ZipMagic $local))) {
            WriteLog "Using local cached file: $local"
            return $local
        }
    }

    $dest = Join-Path $env:TEMP $LocalName

    foreach ($source in $Sources) {
        if (-not $source) { continue }
        try {
            if ($source -like "*drive.google.com*") {
                return Download-GoogleDriveFile -ShareUrl $source -DestinationPath $dest -MinBytes $MinBytes -Kind $Kind
            }

            WriteLog "Downloading: $source"
            Invoke-WebRequest-Retry -Uri $source -OutFile $dest | Out-Null

            if ((Get-Item $dest).Length -lt $MinBytes) { throw "Downloaded file too small" }
            if (-not (Test-NotHtml $dest)) { throw "Downloaded HTML instead of file" }
            if ($Kind -eq "Installer" -and -not (Test-InstallerMagic $dest)) { throw "Bad installer signature" }
            if ($Kind -eq "Zip" -and -not (Test-ZipMagic $dest)) { throw "Bad ZIP signature" }

            return $dest
        }
        catch {
            WriteLog "Source failed: $source :: $($_.Exception.Message)"
        }
    }

    throw "All sources failed for $LocalName"
}

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
        if ($UrlAlsoOpen) {
            Start-Process "chrome.exe" "--new-window $UrlPrimary"
            Start-Process "chrome.exe" $UrlAlsoOpen | Out-Null
        }
        else {
            Start-Process $UrlPrimary | Out-Null
        }
    }
    catch {
        Start-Process $UrlPrimary | Out-Null
    }

    if (-not $TargetPath) {
        Read-Host "When done, press ENTER"
        return $true
    }

    $deadline = (Get-Date).AddMinutes($MaxMinutes)
    while ((Get-Date) -lt $deadline) {
        if (Test-Path $TargetPath) {
            WriteLog "Detected manual download: $TargetPath"
            return $true
        }
        Start-Sleep -Seconds $PollSeconds
    }

    return $false
}

function Get-ChromePath {
    $paths = @(
        "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
        "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"
    )

    foreach ($path in $paths) {
        if (Test-Path $path) { return $path }
    }

    $appPathKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe"
    )

    foreach ($key in $appPathKeys) {
        try {
            $chromePath = (Get-Item -Path $key -ErrorAction Stop).GetValue("")
            if ($chromePath -and (Test-Path $chromePath)) { return $chromePath }
        }
        catch {}
    }

    return $null
}

function Test-ChromeInstalled {
    if (Get-ChromePath) { return $true }

    $keys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    foreach ($key in $keys) {
        $hit = Get-ChildItem $key -ErrorAction SilentlyContinue |
            ForEach-Object { try { Get-ItemProperty $_.PSPath } catch {} } |
            Where-Object { $_.DisplayName -like "Google Chrome*" }
        if ($hit) { return $true }
    }

    return $false
}

function Install-Chrome {
    if (Test-ChromeInstalled) {
        Report "Chrome already installed."
        return $true
    }

    $installed = $false

    if (Get-Command winget -ErrorAction SilentlyContinue) {
        try {
            WriteLog "Installing Chrome with winget."
            winget install --id Google.Chrome --silent --accept-source-agreements --accept-package-agreements | Out-Null
            Start-Sleep -Seconds 5
            $installed = Test-ChromeInstalled
        }
        catch {
            WriteLog "Chrome winget install failed: $($_.Exception.Message)"
        }
    }

    if (-not $installed) {
        $chromeMsi = Join-Path $WorkDir "GoogleChromeStandaloneEnterprise64.msi"

        if (-not ((Test-Path $chromeMsi) -and (Test-InstallerMagic $chromeMsi))) {
            WriteLog "Chrome MSI not found. Downloading Chrome MSI to $chromeMsi"
            try {
                Invoke-WebRequest-Retry -Uri $FALLBACK_CHROME_MSI -OutFile $chromeMsi | Out-Null
            }
            catch {
                WriteLog "Chrome MSI download failed: $($_.Exception.Message)"
            }
        }

        if ((Test-Path $chromeMsi) -and (Test-InstallerMagic $chromeMsi)) {
            WriteLog "Installing Chrome from $chromeMsi"
            Start-Process msiexec.exe -ArgumentList "/i `"$chromeMsi`" /qn /norestart" -Wait
            Start-Sleep -Seconds 5
            $installed = Test-ChromeInstalled
        }
        else {
            WriteLog "Chrome MSI is not available. Skipping MSI install."
        }
    }

    if (-not $installed) {
        $chromeExeInstaller = Join-Path $WorkDir "ChromeSetup.exe"
        $chromeExeUrl = "https://dl.google.com/chrome/install/latest/chrome_installer.exe"

        WriteLog "Downloading Chrome online installer to $chromeExeInstaller"
        Invoke-WebRequest-Retry -Uri $chromeExeUrl -OutFile $chromeExeInstaller | Out-Null

        if (-not ((Test-Path $chromeExeInstaller) -and (Test-InstallerMagic $chromeExeInstaller))) {
            throw "Chrome online installer was not downloaded correctly."
        }

        WriteLog "Installing Chrome from online installer."
        Start-Process -FilePath $chromeExeInstaller -ArgumentList "/silent /install" -Wait
        Start-Sleep -Seconds 10
        $installed = Test-ChromeInstalled
    }

    if (-not $installed) {
        throw "Chrome installer completed, but Chrome was not detected."
    }

    Report "Chrome installed."
    return $true
}

function Install-ChromeRemoteDesktop {
    $crdLocal = $null

    try {
        $crdLocal = Get-FromSources -LocalName "chromeremotedesktophost.msi" -Sources @($GDRIVE_CRD_MSI, $FALLBACK_CRD_MSI) -Kind Installer
    }
    catch {
        WriteLog "CRD auto-download failed: $($_.Exception.Message)"
    }

    if (-not $crdLocal) {
        $target = Join-Path $env:USERPROFILE "Downloads\chromeremotedesktophost.msi"
        $msg = "Download Chrome Remote Desktop Host and save it as: $target. The script will continue when the file appears."
        [void](Open-ManualAndWait -UrlPrimary $FALLBACK_CRD_MSI -UrlAlsoOpen $GDRIVE_FOLDER_ROOT -Message $msg -TargetPath $target)
        if (Test-Path $target) { $crdLocal = $target }
    }

    if ($crdLocal) {
        Start-Process msiexec.exe -ArgumentList "/i `"$crdLocal`" /qn /norestart" -Wait -NoNewWindow
    }

    $hostExe = "$env:ProgramFiles\Google\Chrome Remote Desktop\CurrentVersion\remoting_host.exe"
    $svc = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "Chrome Remote Desktop*" }

    if ((Test-Path $hostExe) -or $svc) {
        Report "Chrome Remote Desktop Host installed."
    }
    else {
        Start-Process "https://remotedesktop.google.com/access" | Out-Null
        $Global:ChangeReport += "ACTION NEEDED: Finish Chrome Remote Desktop setup in browser."
    }
}

function Configure-ChromeRemoteDesktopFirewall {
    $hostExe = "$env:ProgramFiles\Google\Chrome Remote Desktop\CurrentVersion\remoting_host.exe"

    if (Test-Path $hostExe) {
        New-NetFirewallRule -DisplayName "Chrome Remote Desktop Inbound" -Direction Inbound -Program $hostExe -Action Allow -Protocol TCP -Profile Any -ErrorAction SilentlyContinue | Out-Null
        New-NetFirewallRule -DisplayName "Chrome Remote Desktop Outbound" -Direction Outbound -Program $hostExe -Action Allow -Protocol TCP -Profile Any -ErrorAction SilentlyContinue | Out-Null
    }

    Start-Process "https://remotedesktop.google.com/access" | Out-Null
    Report "Chrome Remote Desktop firewall rules checked and access page opened."
}

function Get-PythonCommand {
    if (Get-Command python -ErrorAction SilentlyContinue) { return "python" }
    if (Get-Command py -ErrorAction SilentlyContinue) { return "py -3" }
    return $null
}

function Refresh-Path {
    $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $env:Path = "$machinePath;$userPath"
}

function Ensure-Python {
    if (Get-Command python -ErrorAction SilentlyContinue) {
        Report "Python already available in PATH as: python"
        return "python"
    }

    $pythonInstaller = $null    
    
    try {
        $pythonInstaller = Get-FromSources -LocalName "python_installer.exe" -Sources @($GDRIVE_PY_EXE, $FALLBACK_PY_EXE) -Kind Installer
    }
    catch {
        WriteLog "Python auto-download failed: $($_.Exception.Message)"
    }

    if (-not $pythonInstaller) {
        [void](Open-ManualAndWait -UrlPrimary "https://www.python.org/downloads/windows/" -Message "Download and install Python 3.x 64-bit. IMPORTANT: check Add Python to PATH. Press ENTER here when finished.")
    }
    else {
        Start-Process -FilePath $pythonInstaller -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1 Include_test=0 Include_pip=1" -Wait -NoNewWindow
    }

    Refresh-Path
    $pythonCommand = if (Get-Command python -ErrorAction SilentlyContinue) { "python" } else { $null }

    if (-not $pythonCommand) {
        throw "Python was not detected in PATH. Restart Windows, then run this script again."
    }

    Report "Python installed and available in PATH as: $pythonCommand"
    return $pythonCommand
}

function Invoke-Python {
    param(
        [string]$PythonCommand,
        [string[]]$Arguments
    )

    if ($PythonCommand -eq "py -3") {
        & py -3 @Arguments
    }
    else {
        & python @Arguments
    }

    if ($LASTEXITCODE -ne 0) {
        throw "Python command failed: $PythonCommand $($Arguments -join ' ')"
    }
}

function Install-TwidoSuite {
    $zip = $null

    try {
        $zip = Get-FromSources -LocalName "TwidoSuite.2.33.MultiLanguages.zip" -Sources @($GDRIVE_TWIDO_ZIP) -MinBytes 5MB -Kind Zip
    }
    catch {
        WriteLog "Twido auto-download failed: $($_.Exception.Message)"
    }

    if (-not $zip) {
        foreach ($candidate in @(
            (Join-Path $env:USERPROFILE "Downloads\TwidoSuite.2.33.MultiLanguages.zip"),
            (Join-Path $env:USERPROFILE "Desktop\TwidoSuite.2.33.MultiLanguages.zip")
        )) {
            if ((Test-Path $candidate) -and (Test-ZipMagic $candidate)) {
                $zip = $candidate
                break
            }
        }
    }

    if (-not $zip) {
        $target = Join-Path $env:USERPROFILE "Downloads\TwidoSuite.2.33.MultiLanguages.zip"
        $msg = "Drive will open. Download Twido and save it as: $target. The script continues when the file appears."
        [void](Open-ManualAndWait -UrlPrimary $GDRIVE_TWIDO_ZIP -UrlAlsoOpen $GDRIVE_FOLDER_ROOT -Message $msg -TargetPath $target)
        if ((Test-Path $target) -and (Test-ZipMagic $target)) { $zip = $target }
    }

    if (-not $zip) { throw "Twido ZIP not available." }

    $extractRoot = Join-Path $env:TEMP "TwidoSuite_extract"
    if (Test-Path $extractRoot) { Remove-Item $extractRoot -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -ItemType Directory -Path $extractRoot -Force | Out-Null

    Expand-Archive -Path $zip -DestinationPath $extractRoot -Force
    $setup = Get-ChildItem -Path $extractRoot -Filter "TwidoSuiteInstaller.exe" -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1

    if (-not $setup) { throw "TwidoSuiteInstaller.exe not found after extracting ZIP." }

    Start-Process -FilePath $setup.FullName -Wait
    Report "Twido Suite installer launched."
}

function Install-MachineExpertBasic {
    $installer = $null

    try {
        $installer = Get-FromSources -LocalName "MachineExpertBasic_Setup.exe" -Sources @($GDRIVE_MEB_EXE) -MinBytes 450MB -Kind Installer
    }
    catch {
        WriteLog "Machine Expert auto-download failed: $($_.Exception.Message)"
    }

    if (-not $installer) {
        foreach ($candidate in @(
            (Join-Path $env:USERPROFILE "Downloads\MachineExpertBasic_Setup.exe"),
            (Join-Path $env:USERPROFILE "Desktop\MachineExpertBasic_Setup.exe")
        )) {
            if ((Test-Path $candidate) -and (Test-InstallerMagic $candidate)) {
                $installer = $candidate
                break
            }
        }
    }

    if (-not $installer) {
        $target = Join-Path $env:USERPROFILE "Downloads\MachineExpertBasic_Setup.exe"
        $msg = "Drive will open. Download Machine Expert Basic and save it as: $target. The script continues when the file appears."
        [void](Open-ManualAndWait -UrlPrimary $GDRIVE_MEB_EXE -UrlAlsoOpen $GDRIVE_FOLDER_ROOT -Message $msg -TargetPath $target)
        if ((Test-Path $target) -and (Test-InstallerMagic $target)) { $installer = $target }
    }

    if (-not $installer) { throw "Machine Expert Basic installer not available." }

    $silentWorked = $false
    foreach ($switch in @("/S", "/silent", "/verysilent", "/qn", "/quiet", "/s", "/passive")) {
        try {
            Start-Process -FilePath $installer -ArgumentList $switch -Wait -NoNewWindow -ErrorAction Stop
            $silentWorked = $true
            break
        }
        catch {}
    }

    if (-not $silentWorked) {
        Start-Process -FilePath $installer -Wait
    }

    Report "Machine Expert Basic installed or launched for manual install."
}

function Ensure-ClearType {
    New-Item -Path "HKCU:\Control Panel\Desktop" -Force | Out-Null
    Set-ItemProperty "HKCU:\Control Panel\Desktop" -Name "FontSmoothing" -Type String -Value "2"
    Set-ItemProperty "HKCU:\Control Panel\Desktop" -Name "FontSmoothingType" -Type DWord -Value 2
    Set-ItemProperty "HKCU:\Control Panel\Desktop" -Name "FontSmoothingGamma" -Type DWord -Value 1900 -ErrorAction SilentlyContinue
    Set-ItemProperty "HKCU:\Control Panel\Desktop" -Name "FontSmoothingOrientation" -Type DWord -Value 1 -ErrorAction SilentlyContinue
    rundll32.exe user32.dll,UpdatePerUserSystemParameters
    Report "ClearType enabled."
}

function Configure-PowerSettings {
    powercfg /HIBERNATE OFF
    powercfg -Change -standby-timeout-ac 0
    powercfg -Change -monitor-timeout-ac 0
    powercfg -Change -disk-timeout-ac 0
    powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_VIDEO ADAPTBRIGHT 0
    powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_SLEEP HYBRIDSLEEP 0
    powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_SLEEP STANDBYIDLE 0
    powercfg -SetActive SCHEME_CURRENT
    Report "Power settings set to always-on."
}

function Configure-WindowsUpdatePolicy {
    New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Force | Out-Null
    New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
    Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Type DWord -Value 1
    Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Type DWord -Value 2
    Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -Type DWord -Value 1

    foreach ($serviceName in @("wuauserv", "UsoSvc", "BITS", "DoSvc", "WaaSMedicSvc")) {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($service) {
            try { Stop-Service $serviceName -Force -ErrorAction SilentlyContinue } catch {}
            try { Set-Service $serviceName -StartupType Disabled -ErrorAction SilentlyContinue } catch {}
        }
    }

    Report "Windows Update policies/services adjusted."
}

function Disable-OneDrive {
    Get-Process OneDrive -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

    $sys = "$env:SystemRoot\System32\OneDriveSetup.exe"
    $wow = "$env:SystemRoot\SysWOW64\OneDriveSetup.exe"
    if (Test-Path $sys) { & $sys /uninstall | Out-Null }
    if (Test-Path $wow) { & $wow /uninstall | Out-Null }

    New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Force | Out-Null
    Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSync" -Type DWord -Value 1
    Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1

    Get-ScheduledTask -TaskName "*OneDrive*" -ErrorAction SilentlyContinue | Disable-ScheduledTask -ErrorAction SilentlyContinue | Out-Null
    Report "OneDrive removed/disabled."
}

function Reduce-EdgePrompts {
    New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Force | Out-Null
    Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "HideFirstRunExperience" -Type DWord -Value 1
    Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "DefaultBrowserSettingEnabled" -Type DWord -Value 0
    Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "CreateDesktopShortcutDefault" -Type DWord -Value 0
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "DisableEdgeDesktopShortcutCreation" /t REG_DWORD /d 1 /f | Out-Null
    Report "Edge first-run prompts and desktop shortcut creation reduced."
}

function Get-DefaultRouteIfIndex {
    (Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
        Sort-Object -Property RouteMetric, Publish -Descending:$false |
        Select-Object -First 1).ifIndex
}

function Get-PLCSuffix {
    $match = [regex]::Match($env:COMPUTERNAME, "([A-Za-z])(?!.*[A-Za-z])")
    if ($match.Success) { return $match.Groups[1].Value.ToUpper() }
    return "A"
}

function Set-PLCAdapter {
    param(
        [string]$IPAddress = "192.168.1.100",
        [int]$Prefix = 24
    )

    $defaultIf = Get-DefaultRouteIfIndex
    $candidates = Get-NetAdapter -Physical |
        Where-Object {
            $_.Status -eq "Up" -and
            $_.HardwareInterface -and
            $_.MediaType -in 802.3, "Ethernet" -and
            $_.ifIndex -ne $defaultIf -and
            $_.Name -notmatch "vEthernet|Bluetooth|Wi-?Fi"
        }

    if (-not $candidates) {
        throw "No PLC NIC candidate found. Connect the second Ethernet adapter and try again."
    }

    $nic = $candidates | Where-Object { $_.InterfaceDescription -match "Realtek.*USB" } | Select-Object -First 1
    if (-not $nic) { $nic = $candidates | Select-Object -First 1 }

    $newAlias = "PLC$(Get-PLCSuffix)"
    if ($nic.Name -ne $newAlias) {
        Rename-NetAdapter -Name $nic.Name -NewName $newAlias -PassThru | Out-Null
    }    Set-NetIPInterface -InterfaceAlias $newAlias -Dhcp Disabled -AddressFamily IPv4 -ErrorAction SilentlyContinue
    Get-NetIPAddress -InterfaceAlias $newAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -ne $IPAddress } |
        Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue

    if (-not (Get-NetIPAddress -InterfaceAlias $newAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -eq $IPAddress })) {
        New-NetIPAddress -InterfaceAlias $newAlias -IPAddress $IPAddress -PrefixLength $Prefix -ErrorAction Stop | Out-Null
    }

    Set-NetConnectionProfile -InterfaceAlias $newAlias -NetworkCategory Private -ErrorAction SilentlyContinue
    Disable-NetAdapterBinding -Name $newAlias -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
    Set-DnsClientServerAddress -InterfaceAlias $newAlias -ResetServerAddresses

    Report "PLC NIC '$newAlias' set to $IPAddress/$Prefix with no gateway."
}

function Get-FirstExistingPath {
    param([string[]]$Paths)

    foreach ($path in $Paths) {
        if (Test-Path $path) { return $path }
    }

    return $null
}

function Save-XmlDocument {
    param(
        [xml]$Xml,
        [string]$Path
    )

    $settings = New-Object System.Xml.XmlWriterSettings
    $settings.Indent = $true
    $settings.Encoding = New-Object System.Text.UTF8Encoding($false)

    $writer = [System.Xml.XmlWriter]::Create($Path, $settings)
    try {
        $Xml.Save($writer)
    }
    finally {
        $writer.Close()
    }
}

function Update-RaulSettingsFile {
    param(
        [string]$Folder,
        [string]$TabName,
        [string]$ProjectName
    )

    $settingsPath = Get-FirstExistingPath @(
        (Join-Path $Folder "settings.xml"),
        (Join-Path $Folder "settings")
    )

    if (-not $settingsPath) {
        throw "Could not find settings.xml or settings in $Folder"
    }

    [xml]$xml = Get-Content $settingsPath -Raw

    if (-not $xml.Settings) {
        throw "Invalid settings file. Missing <Settings> root in $settingsPath"
    }

    $xml.Settings.LocationLog = "$TabName!A:D"
    $xml.Settings.ProjectName = $ProjectName

    Save-XmlDocument -Xml $xml -Path $settingsPath
    Report "Updated RAUL settings: $settingsPath"
}

function Update-RaulManualConfig {
    param(
        [string]$ManualFolder,
        [string]$TabName
    )

    $configPath = Get-FirstExistingPath @(
        (Join-Path $ManualFolder "raul_config.xml"),
        (Join-Path $ManualFolder "raul_config")
    )

    if (-not $configPath) {
        $Global:ChangeReport += "WARNING: Could not find raul_config.xml or raul_config in $ManualFolder"
        return
    }

    [xml]$xml = Get-Content $configPath -Raw

    if (-not $xml.raul_config.history.tab_name) {
        throw "Invalid RAUL config. Missing <history><tab_name> in $configPath"
    }

    $xml.raul_config.history.tab_name = $TabName
    Save-XmlDocument -Xml $xml -Path $configPath

    Report "Updated RAUL manual config: $configPath"
}

function Install-RaulPythonPackages {
    param(
        [string]$PythonCommand,
        [string]$DashFolder
    )

    $requirementsPath = Join-Path $DashFolder "requirements.txt"

    Invoke-Python -PythonCommand $PythonCommand -Arguments @("-m", "pip", "install", "--upgrade", "pip")

    if (Test-Path $requirementsPath) {
        Push-Location $DashFolder
        try {
            Invoke-Python -PythonCommand $PythonCommand -Arguments @("-m", "pip", "install", "-r", "requirements.txt")
        }
        finally {
            Pop-Location
        }
        Report "Installed RAULDASH requirements.txt."
    }
    else {
        $Global:ChangeReport += "WARNING: requirements.txt was not found in $DashFolder"
    }

    Invoke-Python -PythonCommand $PythonCommand -Arguments @("-m", "pip", "install", "flask")
    Report "Installed Flask."
}

function Install-RaulApp {
    param(
        [string]$PythonCommand,
        [string]$TabName,
        [string]$ProjectName,
        [string]$ManualServerUrl
    )

    $zipPath = Join-Path $WorkDir "RAUL 2.0.zip"
    $extractTemp = Join-Path $WorkDir "raul_extract"

    Download-GoogleDriveFile -ShareUrl $GDRIVE_RAUL_ZIP -DestinationPath $zipPath -MinBytes 1MB -Kind Zip | Out-Null

    if (Test-Path $extractTemp) { Remove-Item $extractTemp -Recurse -Force }
    New-Item -ItemType Directory -Path $extractTemp -Force | Out-Null

    Expand-Archive -Path $zipPath -DestinationPath $extractTemp -Force

    $dashSource = Get-ChildItem -Path $extractTemp -Directory -Recurse | Where-Object { $_.Name -ieq "RAULDASH" } | Select-Object -First 1
    $manualSource = Get-ChildItem -Path $extractTemp -Directory -Recurse | Where-Object { $_.Name -ieq "RAULMANUAL" } | Select-Object -First 1

    if (-not $dashSource) { throw "RAULDASH folder was not found inside RAUL ZIP." }
    if (-not $manualSource) { throw "RAULMANUAL folder was not found inside RAUL ZIP." }

    if (Test-Path $InstallRoot) {
        $backupPath = "$InstallRoot.backup.$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        Move-Item -Path $InstallRoot -Destination $backupPath
        Report "Existing RAUL install backed up to $backupPath"
    }

    New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null
    Copy-Item -Path $dashSource.FullName -Destination $InstallRoot -Recurse -Force
    Copy-Item -Path $manualSource.FullName -Destination $InstallRoot -Recurse -Force

    $dashFolder = Join-Path $InstallRoot "RAULDASH"
    $manualFolder = Join-Path $InstallRoot "RAULMANUAL"

    Update-RaulSettingsFile -Folder $dashFolder -TabName $TabName -ProjectName $ProjectName
    Update-RaulSettingsFile -Folder $manualFolder -TabName $TabName -ProjectName $ProjectName
    Update-RaulManualConfig -ManualFolder $manualFolder -TabName $TabName
    Install-RaulPythonPackages -PythonCommand $PythonCommand -DashFolder $dashFolder
    Create-RaulStartupFile -PythonCommand "python" -DashFolder $dashFolder -ManualFolder $manualFolder -ManualServerUrl $ManualServerUrl

    Report "RAUL 2.0 installed to $InstallRoot"
}

function Create-RaulStartupFile {
    param(
        [string]$PythonCommand,
        [string]$DashFolder,
        [string]$ManualFolder,
        [string]$ManualServerUrl
    )

    $startupFolder = [Environment]::GetFolderPath("Startup")
    $batPath = Join-Path $startupFolder $StartupBatName

    $bat = @"
@echo off

REM Start RAUL Dash
start "RAUL Dash" cmd /k "title RAUL Dash && cd /d ""$DashFolder"" && $PythonCommand raultodash.py"

REM Wait for RAULDASH menu to load
timeout /t 3 /nobreak >nul

REM Select option 5 in RAUL Dash
powershell -NoProfile -ExecutionPolicy Bypass -Command "Add-Type -AssemblyName Microsoft.VisualBasic; Add-Type -AssemblyName System.Windows.Forms; [Microsoft.VisualBasic.Interaction]::AppActivate('RAUL Dash'); Start-Sleep -Milliseconds 500; [System.Windows.Forms.SendKeys]::SendWait('5{ENTER}')"

REM Start RAUL Manual server
start "RAUL Manual" cmd /k "title RAUL Manual && cd /d ""$ManualFolder"" && $PythonCommand raul_manual.py"

REM Wait for manual server to start
timeout /t 5 /nobreak >nul

REM Open first server in browser
start "" "$ManualServerUrl"
"@

    $bat | Out-File -FilePath $batPath -Encoding ASCII -Force
    Report "Created RAUL startup file: $batPath"
}

# ==================== MAIN ====================
Assert-Admin

Write-Host ""
Write-Host "RAUL full setup for Windows 10/11" -ForegroundColor Cyan
Write-Host "Log file: $Log"
Write-Host ""

$installChrome = Prompt-YesNo "Install Google Chrome?" $true
$installCRD = Prompt-YesNo "Install Chrome Remote Desktop Host?" $true
$installTwido = Prompt-YesNo "Install Twido Suite?" $false
$installMachineExpert = Prompt-YesNo "Install Schneider Machine Expert Basic?" $false
$installPython = Prompt-YesNo "Install/check Python and PATH?" $true
$configurePLC = Prompt-YesNo "Configure PLC Ethernet adapter to 192.168.1.100?" $true
$disableUpdates = Prompt-YesNo "Disable automatic Windows Update services/policies?" $true
$disableOneDrive = Prompt-YesNo "Remove/disable OneDrive?" $true

Write-Host ""
$desiredComputerName = Read-Host "Enter computer name, or press ENTER to keep $env:COMPUTERNAME"
$wantDpi = Read-Host "Set display scaling to 125%? (Y/N, default N)"

Write-Host ""
$tabName = (Read-Host "Enter RAUL LocationLog tab name").Trim()
$projectName = (Read-Host "Enter RAUL ProjectName").Trim()
$manualServerUrlInput = (Read-Host "Enter first RAULMANUAL server URL, or press ENTER for http://127.0.0.1:5000").Trim()

if ([string]::IsNullOrWhiteSpace($tabName)) { throw "LocationLog tab name cannot be blank." }if ([string]::IsNullOrWhiteSpace($projectName)) { throw "ProjectName cannot be blank." }

$manualServerUrl = if ([string]::IsNullOrWhiteSpace($manualServerUrlInput)) { "http://127.0.0.1:5000" } else { $manualServerUrlInput }
$needReboot = $false

if ($desiredComputerName -and $desiredComputerName -ne $env:COMPUTERNAME) {
    Try-Run { Rename-Computer -NewName $desiredComputerName -Force } "Rename computer to $desiredComputerName"
    $needReboot = $true
}

if ($wantDpi -match "^[Yy]") {
    Try-Run {
        New-Item -Path "HKCU:\Control Panel\Desktop" -Force | Out-Null
        Set-ItemProperty "HKCU:\Control Panel\Desktop" -Name "LogPixels" -Type DWord -Value 120
        Set-ItemProperty "HKCU:\Control Panel\Desktop" -Name "Win8DpiScaling" -Type DWord -Value 1
    } "Set display scaling to 125%"
    $needReboot = $true
}

Try-Run { Ensure-ClearType } "Enable ClearType"

if (-not (Wait-Network -TimeoutSec 120)) {
    Write-Warning "Network was not detected, but the script will continue."
}

Try-Run {
    Add-MpPreference -ExclusionPath $StableDir -ErrorAction SilentlyContinue
    Add-MpPreference -ExclusionProcess "powershell.exe" -ErrorAction SilentlyContinue
} "Defender exclusions"

if ($installChrome) {
    Try-Run { Install-Chrome } "Install Chrome"

    $chromePath = Get-ChromePath
    if ($chromePath) {
        Try-Run { Start-Process "ms-settings:defaultapps?apiname=Microsoft.Chrome" -WindowStyle Minimized; Start-Sleep 3 } "Open Chrome default apps page"
        Try-Run {
            Start-Process $chromePath "--new-window https://accounts.google.com/ServiceLogin"
            Write-Host ""
            Write-Host "Sign into Chrome as service@thetrivialcompany.com if this PC uses that account."
            Read-Host "Press ENTER after Chrome sign-in is complete, or press ENTER to skip"
        } "Chrome account sign-in prompt"
    }
    else {
        Write-Warning "Chrome is still not installed. Skipping Chrome default-app and sign-in steps."
        $Global:ChangeReport += "FAILED: Chrome setup steps skipped because Chrome was not installed."
    }
}
else {
    Report "Skipped Chrome."
}

if ($installCRD) {
    Try-Run { Install-ChromeRemoteDesktop } "Install Chrome Remote Desktop Host"
}
else {
    Report "Skipped Chrome Remote Desktop Host."
}

Try-Run { DISM /Online /Enable-Feature /FeatureName:NetFx3 /All /Quiet /NoRestart | Out-Null } "Enable .NET 3.5"

if ($installPython) {
    $pythonCommand = Ensure-Python
}
else {
    if (Get-Command python -ErrorAction SilentlyContinue) {
        $pythonCommand = "python"
    }
    else {
        throw "Python is required for RAUL, but the python command was not found and Python install/check was skipped."
    }
}

if ($installTwido) {
    Try-Run { Install-TwidoSuite } "Install Twido Suite"
}
else {
    Report "Skipped Twido Suite."
}

if ($installMachineExpert) {
    Try-Run { Install-MachineExpertBasic } "Install Schneider Machine Expert Basic"
}
else {
    Report "Skipped Schneider Machine Expert Basic."
}

Try-Run { Configure-PowerSettings } "Keep system awake"

if ($disableUpdates) {
    Try-Run { Configure-WindowsUpdatePolicy } "Disable automatic Windows Update services/policies"
}
else {
    Report "Skipped Windows Update changes."
}

if ($disableOneDrive) {
    Try-Run { Disable-OneDrive } "Remove/disable OneDrive"
}
else {
    Report "Skipped OneDrive changes."
}

Try-Run { Reduce-EdgePrompts } "Reduce Edge prompts/shortcuts"

if ($configurePLC) {
    Try-Run { Set-PLCAdapter -IPAddress "192.168.1.100" -Prefix 24 } "Configure PLC NIC"
}
else {
    Report "Skipped PLC NIC configuration."
}

if ($installCRD) {
    Try-Run { Configure-ChromeRemoteDesktopFirewall } "Configure Chrome Remote Desktop firewall/open access page"
}

Try-Run {
    Install-RaulApp -PythonCommand $pythonCommand -TabName $tabName -ProjectName $projectName -ManualServerUrl $manualServerUrl
} "Install and configure RAUL 2.0"

Write-Host ""
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "   RAUL FULL SETUP COMPLETED" -ForegroundColor Green
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Summary:" -ForegroundColor Yellow
$Global:ChangeReport | ForEach-Object { Write-Host " - $_" }
Write-Host ""
Write-Host "Detailed log: $Log" -ForegroundColor DarkGray

if ($needReboot) {
    Write-Host ""
    Write-Host "A reboot is recommended because the computer name or DPI was changed." -ForegroundColor Yellow
    if (Prompt-YesNo "Restart now?" $false) {
        Restart-Computer -Force
    }
}

Write-Host ""
Read-Host "Press ENTER to close"
