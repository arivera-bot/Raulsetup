<#
Install-RAUL-2.0.ps1

This single script:
  1. Downloads RAUL 2.0.zip from Google Drive.
  2. Extracts RAULDASH and RAULMANUAL.
  3. Prompts for LocationLog/tab name and ProjectName.
  4. Updates both settings XML files.
  5. Updates RAULMANUAL raul_config tab_name.
  6. Installs Python if it is missing.
  7. Runs pip install -r requirements.txt from RAULDASH.
  8. Installs Flask.
  9. Creates a Windows startup BAT that starts both apps, selects option 5
     in RAULDASH, and opens the first RAULMANUAL server URL.

Run from PowerShell:
  powershell -NoProfile -ExecutionPolicy Bypass -File .\Install-RAUL-2.0.ps1
#>

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# -------------------- Settings you may change --------------------
$DriveZipUrl = "https://drive.google.com/file/d/1EYRUZByBWuTKHPfY0sN6Lw_IQgSYTmu_/view?usp=sharing"
$InstallRoot = Join-Path $env:USERPROFILE "Downloads\RAUL 2.0"
$DefaultManualServerUrl = "http://127.0.0.1:5000"
$PythonInstallerUrl = "https://www.python.org/ftp/python/3.12.6/python-3.12.6-amd64.exe"
$StartupBatName = "Start_RAUL_Apps.bat"
# ------------------------------------------------------------------

$WorkDir = Join-Path $env:ProgramData "Trivial\RAULInstaller"
$ZipPath = Join-Path $WorkDir "RAUL 2.0.zip"
$ExtractTemp = Join-Path $WorkDir "extract"
$LogPath = Join-Path $WorkDir "install-raul.log"

New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null

function Write-Log {
    param([string]$Message)

    $line = "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
    Write-Host $line
    $line | Out-File -FilePath $LogPath -Append -Encoding utf8
}

function Get-GoogleDriveFileId {
    param([string]$Url)

    if ($Url -match "/d/([A-Za-z0-9_-]+)") {
        return $Matches[1]
    }

    if ($Url -match "id=([A-Za-z0-9_-]+)") {
        return $Matches[1]
    }

    throw "Could not find a Google Drive file ID in this URL: $Url"
}

function Test-ZipFile {
    param([string]$Path)

    if (-not (Test-Path $Path)) {
        return $false
    }

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

function Download-GoogleDriveFile {
    param(
        [string]$ShareUrl,
        [string]$DestinationPath
    )

    $fileId = Get-GoogleDriveFileId -Url $ShareUrl
    $baseUrl = "https://docs.google.com/uc?export=download&id=$fileId"

    if (Test-Path $DestinationPath) {
        Remove-Item $DestinationPath -Force
    }

    $headers = @{
        "User-Agent" = "Mozilla/5.0"
        "Accept" = "*/*"
    }

    Write-Log "Downloading RAUL zip from Google Drive..."

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
        elseif ($response.Content -match 'name="confirm"\s+value="([0-9A-Za-z_-]+)"') {
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

    if (-not (Test-ZipFile -Path $DestinationPath)) {
        throw "Download finished, but the file is not a valid ZIP. Make sure the Google Drive file is shared so anyone with the link can download it."
    }

    Write-Log "Downloaded ZIP to $DestinationPath"
}

function Get-PythonCommand {
    $python = Get-Command python -ErrorAction SilentlyContinue
    if ($python) {
        return "python"
    }

    $py = Get-Command py -ErrorAction SilentlyContinue
    if ($py) {
        return "py -3"
    }

    return $null
}

function Ensure-Python {
    $pythonCommand = Get-PythonCommand

    if ($pythonCommand) {
        Write-Log "Python found: $pythonCommand"
        return $pythonCommand
    }

    $installer = Join-Path $WorkDir "python-installer.exe"

    Write-Log "Python not found. Downloading Python installer..."
    Invoke-WebRequest -UseBasicParsing -Uri $PythonInstallerUrl -OutFile $installer -TimeoutSec 3600

    Write-Log "Installing Python for the current user..."
    Start-Process -FilePath $installer -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1 Include_test=0 Include_pip=1" -Wait

    $env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [Environment]::GetEnvironmentVariable("Path", "User")
    $pythonCommand = Get-PythonCommand

    if (-not $pythonCommand) {
        throw "Python installed, but it was not found in PATH. Restart the computer, then run this script again."
    }

    Write-Log "Python installed successfully: $pythonCommand"
    return $pythonCommand
}

function Get-FirstExistingPath {
    param([string[]]$Paths)

    foreach ($path in $Paths) {
        if (Test-Path $path) {
            return $path
        }
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

function Update-SettingsFile {
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
    Write-Log "Updated $settingsPath"
}

function Update-RaulConfig {
    param(
        [string]$ManualFolder,
        [string]$TabName
    )

    $configPath = Get-FirstExistingPath @(
        (Join-Path $ManualFolder "raul_config.xml"),
        (Join-Path $ManualFolder "raul_config")
    )

    if (-not $configPath) {
        Write-Log "WARNING: Could not find raul_config.xml or raul_config in $ManualFolder"
        return
    }

    [xml]$xml = Get-Content $configPath -Raw

    if (-not $xml.raul_config.history.tab_name) {
        throw "Invalid RAUL config. Missing <history><tab_name> in $configPath"
    }

    $xml.raul_config.history.tab_name = $TabName

    Save-XmlDocument -Xml $xml -Path $configPath
    Write-Log "Updated $configPath"
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

function Install-PythonPackages {
    param(
        [string]$PythonCommand,
        [string]$DashFolder
    )

    $requirementsPath = Join-Path $DashFolder "requirements.txt"

    Write-Log "Upgrading pip..."
    Invoke-Python -PythonCommand $PythonCommand -Arguments @("-m", "pip", "install", "--upgrade", "pip")

    if (Test-Path $requirementsPath) {
        Write-Log "Installing RAULDASH requirements from $requirementsPath"
        Push-Location $DashFolder
        try {
            Invoke-Python -PythonCommand $PythonCommand -Arguments @("-m", "pip", "install", "-r", "requirements.txt")
        }
        finally {
            Pop-Location
        }
    }
    else {
        Write-Log "WARNING: requirements.txt was not found in $DashFolder"
    }

    Write-Log "Installing Flask..."
    Invoke-Python -PythonCommand $PythonCommand -Arguments @("-m", "pip", "install", "flask")
}

function Create-StartupFile {
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
    Write-Log "Created startup file: $batPath"

    return $batPath
}

# -------------------- Main install --------------------
Write-Log "==== RAUL 2.0 install started ===="

Write-Host ""
Write-Host "This will install RAUL 2.0 to:"
Write-Host "  $InstallRoot"
Write-Host ""

$tabName = Read-Host "Enter LocationLog tab name"
$projectName = Read-Host "Enter ProjectName"
$manualServerUrlInput = Read-Host "Enter first RAULMANUAL server URL, or press ENTER for $DefaultManualServerUrl"

$tabName = $tabName.Trim()
$projectName = $projectName.Trim()

if ([string]::IsNullOrWhiteSpace($tabName)) {
    throw "LocationLog tab name cannot be blank."
}

if ([string]::IsNullOrWhiteSpace($projectName)) {
    throw "ProjectName cannot be blank."
}

if ([string]::IsNullOrWhiteSpace($manualServerUrlInput)) {
    $manualServerUrl = $DefaultManualServerUrl
}
else {
    $manualServerUrl = $manualServerUrlInput.Trim()
}

Download-GoogleDriveFile -ShareUrl $DriveZipUrl -DestinationPath $ZipPath

if (Test-Path $ExtractTemp) {
    Remove-Item $ExtractTemp -Recurse -Force
}

New-Item -ItemType Directory -Path $ExtractTemp -Force | Out-Null

Write-Log "Extracting ZIP..."
Expand-Archive -Path $ZipPath -DestinationPath $ExtractTemp -Force

$dashSource = Get-ChildItem -Path $ExtractTemp -Directory -Recurse | Where-Object { $_.Name -ieq "RAULDASH" } | Select-Object -First 1
$manualSource = Get-ChildItem -Path $ExtractTemp -Directory -Recurse | Where-Object { $_.Name -ieq "RAULMANUAL" } | Select-Object -First 1

if (-not $dashSource) {
    throw "RAULDASH folder was not found inside the ZIP."
}

if (-not $manualSource) {
    throw "RAULMANUAL folder was not found inside the ZIP."
}

if (Test-Path $InstallRoot) {
    $backupPath = "$InstallRoot.backup.$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    Write-Log "Existing install found. Moving it to $backupPath"
    Move-Item -Path $InstallRoot -Destination $backupPath
}

New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null
Copy-Item -Path $dashSource.FullName -Destination $InstallRoot -Recurse -Force
Copy-Item -Path $manualSource.FullName -Destination $InstallRoot -Recurse -Force

$dashFolder = Join-Path $InstallRoot "RAULDASH"
$manualFolder = Join-Path $InstallRoot "RAULMANUAL"

Update-SettingsFile -Folder $dashFolder -TabName $tabName -ProjectName $projectName
Update-SettingsFile -Folder $manualFolder -TabName $tabName -ProjectName $projectName
Update-RaulConfig -ManualFolder $manualFolder -TabName $tabName

$pythonCommand = Ensure-Python
Install-PythonPackages -PythonCommand $pythonCommand -DashFolder $dashFolder

$startupPath = Create-StartupFile -PythonCommand $pythonCommand -DashFolder $dashFolder -ManualFolder $manualFolder -ManualServerUrl $manualServerUrl

Write-Log "==== RAUL 2.0 install completed ===="

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "RAUL 2.0 SETUP COMPLETE" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Installed to: $InstallRoot"
Write-Host "Startup file: $startupPath"
Write-Host "Install log: $LogPath"
Write-Host ""
Write-Host "The apps will start automatically the next time this Windows user logs in."
Write-Host ""
Read-Host "Press ENTER to close"
