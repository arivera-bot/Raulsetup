<#
Setup-RAUL-Programs-Only.ps1

Purpose:
  Only sets up RAUL 2.0 programs:
    - Downloads RAUL 2.0.zip
    - Extracts RAULDASH and RAULMANUAL
    - Updates settings.xml in both folders
    - Updates RAULMANUAL raul_config.xml tab_name
    - Optionally changes RAULMANUAL port
    - Installs RAULDASH requirements.txt
    - Installs Flask
    - Creates startup BAT for both RAUL programs

Run:
  powershell -NoProfile -ExecutionPolicy Bypass -File .\Setup-RAUL-Programs-Only.ps1
#>

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ===== RAUL DOWNLOAD LINK =====
$RaulZipUrl = "https://drive.google.com/file/d/1EYRUZByBWuTKHPfY0sN6Lw_IQgSYTmu_/view?usp=sharing"

# ===== PATHS =====
$InstallRoot = Join-Path $env:USERPROFILE "Downloads\RAUL 2.0"
$WorkDir = Join-Path $env:TEMP "RAUL_Setup"
$ZipPath = Join-Path $WorkDir "RAUL 2.0.zip"
$ExtractPath = Join-Path $WorkDir "Extracted"
$StartupBatName = "Start_RAUL_Apps.bat"

New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null

function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Cyan
}

function Write-OK {
    param([string]$Message)
    Write-Host "[OK] $Message" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
}

function Get-GoogleDriveFileId {
    param([string]$Url)

    if ($Url -match "/d/([A-Za-z0-9_-]+)") {
        return $Matches[1]
    }

    if ($Url -match "id=([A-Za-z0-9_-]+)") {
        return $Matches[1]
    }

    throw "Could not find Google Drive file ID in URL: $Url"
}

function Test-ZipMagic {
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
        Remove-Item $DestinationPath -Force -ErrorAction SilentlyContinue
    }

    $headers = @{
        "User-Agent" = "Mozilla/5.0"
        "Accept" = "*/*"
    }

    Write-Info "Downloading RAUL 2.0.zip..."

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

    if (-not (Test-ZipMagic -Path $DestinationPath)) {
        throw "Downloaded file is not a valid ZIP. Check Google Drive sharing permissions."
    }

    Write-OK "Downloaded ZIP: $DestinationPath"
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

    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)

    $settings = New-Object System.Xml.XmlWriterSettings
    $settings.Indent = $true
    $settings.Encoding = $utf8NoBom

    $writer = [System.Xml.XmlWriter]::Create($Path, $settings)

    try {
        $Xml.Save($writer)
    }
    finally {
        $writer.Close()
    }
}

function Update-SettingsXml {
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

    [xml]$xml = Get-Content $settingsPath -Raw -Encoding UTF8

    if (-not $xml.Settings) {
        throw "Invalid settings file. Missing <Settings> root in $settingsPath"
    }

    $xml.Settings.LocationLog = "$TabName!A:D"
    $xml.Settings.ProjectName = $ProjectName

    Save-XmlDocument -Xml $xml -Path $settingsPath

    Write-OK "Updated $settingsPath"
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
        throw "Could not find raul_config.xml or raul_config in $ManualFolder"
    }

    [xml]$xml = Get-Content $configPath -Raw -Encoding UTF8

    if (-not $xml.raul_config.history.tab_name) {
        throw "Invalid raul_config file. Could not find <history><tab_name>"
    }

    $xml.raul_config.history.tab_name = $TabName

    Save-XmlDocument -Xml $xml -Path $configPath

    Write-OK "Updated $configPath"
}

function Get-RaulManualPort {
    param([string]$ManualFolder)

    $manualPy = Join-Path $ManualFolder "raul_manual.py"

    if (-not (Test-Path $manualPy)) {
        return $null
    }

    $content = [System.IO.File]::ReadAllText($manualPy, [System.Text.Encoding]::UTF8)

    $match = [regex]::Match($content, 'app\.run\((?s).*?port\s*=\s*(\d+).*?\)')

    if ($match.Success) {
        return [int]$match.Groups[1].Value
    }

    return $null
}

function Update-RaulManualPort {
    param(
        [string]$ManualFolder,
        [int]$Port
    )

    $manualPy = Join-Path $ManualFolder "raul_manual.py"

    if (-not (Test-Path $manualPy)) {
        throw "Could not find raul_manual.py at $manualPy"
    }

    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    $content = [System.IO.File]::ReadAllText($manualPy, [System.Text.Encoding]::UTF8)

    # Match the whole app.run(...) line, even if spacing is different.
    $pattern = '(?m)^\s*app\.run\(.*?\)\s*$'
    $match = [regex]::Match($content, $pattern)

    if (-not $match.Success) {
        throw "Could not find any app.run(...) line in raul_manual.py"
    }

    $newLine = "    app.run(host=""0.0.0.0"", port=$Port, debug=True)"
    $newContent = $content.Remove($match.Index, $match.Length).Insert($match.Index, $newLine)

    [System.IO.File]::WriteAllText($manualPy, $newContent, $utf8NoBom)

    Write-OK "Updated RAULMANUAL port to $Port"
}

function Get-PythonCommand {
    if (Get-Command python -ErrorAction SilentlyContinue) {
        return "python"
    }

    if (Get-Command py -ErrorAction SilentlyContinue) {
        return "py -3"
    }

    return $null
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

function Install-PythonRequirements {
    param(
        [string]$PythonCommand,
        [string]$DashFolder
    )

    $requirements = Join-Path $DashFolder "requirements.txt"

    Write-Info "Upgrading pip..."
    Invoke-Python -PythonCommand $PythonCommand -Arguments @("-m", "pip", "install", "--upgrade", "pip")

    if (Test-Path $requirements) {
        Write-Info "Installing requirements.txt from RAULDASH..."
        Push-Location $DashFolder

        try {
            Invoke-Python -PythonCommand $PythonCommand -Arguments @("-m", "pip", "install", "-r", "requirements.txt")
        }
        finally {
            Pop-Location
        }

        Write-OK "Installed RAULDASH requirements.txt"
    }
    else {
        Write-Warn "requirements.txt not found in $DashFolder"
    }

    Write-Info "Installing Flask..."
    Invoke-Python -PythonCommand $PythonCommand -Arguments @("-m", "pip", "install", "flask")
    Write-OK "Installed Flask"
}

function Update-FirewallForPort {
    param([int]$Port)

    $ruleName = "RAUL Manual Flask Port $Port"

    $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue

    if (-not $existing) {
        New-NetFirewallRule `
            -DisplayName $ruleName `
            -Direction Inbound `
            -Action Allow `
            -Protocol TCP `
            -LocalPort $Port `
            -Profile Any `
            -ErrorAction SilentlyContinue | Out-Null

        Write-OK "Created firewall rule for port $Port"
    }
    else {
        Write-OK "Firewall rule already exists for port $Port"
    }
}

function Create-StartupBat {
    param(
        [string]$DashFolder,
        [string]$ManualFolder,
        [int]$Port
    )

    $startupFolder = [Environment]::GetFolderPath("Startup")
    $batPath = Join-Path $startupFolder $StartupBatName
    $manualUrl = "http://127.0.0.1:$Port"

    $bat = @"
@echo off

REM Start RAUL Dash
start "RAUL Dash" cmd /k "title RAUL Dash && cd /d ""$DashFolder"" && python raultodash.py"

REM Wait for RAULDASH menu to load
timeout /t 3 /nobreak >nul

REM Select option 5 in RAUL Dash
powershell -NoProfile -ExecutionPolicy Bypass -Command "Add-Type -AssemblyName Microsoft.VisualBasic; Add-Type -AssemblyName System.Windows.Forms; [Microsoft.VisualBasic.Interaction]::AppActivate('RAUL Dash'); Start-Sleep -Milliseconds 500; [System.Windows.Forms.SendKeys]::SendWait('5{ENTER}')"

REM Start RAUL Manual server
start "RAUL Manual" cmd /k "title RAUL Manual && cd /d ""$ManualFolder"" && python raul_manual.py"

REM Wait for manual server to start
timeout /t 5 /nobreak >nul

REM Open RAUL Manual locally
start "" "$manualUrl"
"@

    $bat | Out-File -FilePath $batPath -Encoding ASCII -Force

    Write-OK "Created startup file: $batPath"
}

# ================= MAIN =================

Write-Host ""
Write-Host "RAUL PROGRAMS ONLY SETUP" -ForegroundColor Cyan
Write-Host ""

$tabName = Read-Host "Enter LocationLog tab name"
$projectName = Read-Host "Enter ProjectName / Job name"
$portInput = Read-Host "Enter RAULMANUAL port, or press ENTER to leave default/current port"

$tabName = $tabName.Trim()
$projectName = $projectName.Trim()

if ([string]::IsNullOrWhiteSpace($tabName)) {
    throw "LocationLog tab name cannot be blank."
}

if ([string]::IsNullOrWhiteSpace($projectName)) {
    throw "ProjectName / Job name cannot be blank."
}

$changePort = $false
$selectedPort = $null

if (-not [string]::IsNullOrWhiteSpace($portInput)) {
    $selectedPort = [int]$portInput

    if ($selectedPort -lt 1 -or $selectedPort -gt 65535) {
        throw "Invalid port number: $selectedPort"
    }

    $changePort = $true
}

$pythonCommand = Get-PythonCommand

if (-not $pythonCommand) {
    throw "Python was not found. Install Python first and make sure it is available from PATH."
}

Write-OK "Python found: $pythonCommand"

Download-GoogleDriveFile -ShareUrl $RaulZipUrl -DestinationPath $ZipPath

if (Test-Path $ExtractPath) {
    Remove-Item $ExtractPath -Recurse -Force
}

New-Item -ItemType Directory -Path $ExtractPath -Force | Out-Null

Write-Info "Extracting RAUL 2.0.zip..."
Expand-Archive -Path $ZipPath -DestinationPath $ExtractPath -Force

$dashSource = Get-ChildItem -Path $ExtractPath -Directory -Recurse | Where-Object { $_.Name -ieq "RAULDASH" } | Select-Object -First 1
$manualSource = Get-ChildItem -Path $ExtractPath -Directory -Recurse | Where-Object { $_.Name -ieq "RAULMANUAL" } | Select-Object -First 1

if (-not $dashSource) {
    throw "RAULDASH folder was not found inside the ZIP."
}

if (-not $manualSource) {
    throw "RAULMANUAL folder was not found inside the ZIP."
}

if (Test-Path $InstallRoot) {
    $backup = "$InstallRoot.backup.$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    Move-Item -Path $InstallRoot -Destination $backup
    Write-Warn "Existing RAUL install was backed up to:"
    Write-Warn $backup
}

New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null

Copy-Item -Path $dashSource.FullName -Destination $InstallRoot -Recurse -Force
Copy-Item -Path $manualSource.FullName -Destination $InstallRoot -Recurse -Force

$DashFolder = Join-Path $InstallRoot "RAULDASH"
$ManualFolder = Join-Path $InstallRoot "RAULMANUAL"

Update-SettingsXml -Folder $DashFolder -TabName $tabName -ProjectName $projectName
Update-SettingsXml -Folder $ManualFolder -TabName $tabName -ProjectName $projectName
Update-RaulConfig -ManualFolder $ManualFolder -TabName $tabName

if ($changePort) {
    Update-RaulManualPort -ManualFolder $ManualFolder -Port $selectedPort
    $finalPort = $selectedPort
}
else {
    $detectedPort = Get-RaulManualPort -ManualFolder $ManualFolder

    if ($detectedPort) {
        $finalPort = $detectedPort
        Write-Info "Port left unchanged. Detected current port: $finalPort"
    }
    else {
        $finalPort = 5000
        Write-Warn "Could not detect current port. Startup file will use 5000."
    }
}

Install-PythonRequirements -PythonCommand $pythonCommand -DashFolder $DashFolder
Update-FirewallForPort -Port $finalPort
Create-StartupBat -DashFolder $DashFolder -ManualFolder $ManualFolder -Port $finalPort

Write-Host ""
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "RAUL PROGRAM SETUP COMPLETE" -ForegroundColor Green
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Install folder: $InstallRoot"
Write-Host "LocationLog: $tabName!A:D"
Write-Host "ProjectName / Job name: $projectName"
Write-Host "RAULMANUAL local URL: http://127.0.0.1:$finalPort"
Write-Host ""
Write-Host "For network access, use:"
Write-Host "http://THIS-COMPUTER-IP:$finalPort"
Write-Host ""
Read-Host "Press ENTER to close"
