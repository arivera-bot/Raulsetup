<#
Update-RAUL-Settings.ps1

Purpose:
  Change RAUL tab name, project/job name, computer name, and RAULMANUAL port.

Run as Administrator:
  powershell -NoProfile -ExecutionPolicy Bypass -File .\Update-RAUL-Settings.ps1
#>

$ErrorActionPreference = "Stop"

# Default RAUL install path
$RaulRoot = Join-Path $env:USERPROFILE "Downloads\RAUL 2.0"
$DashFolder = Join-Path $RaulRoot "RAULDASH"
$ManualFolder = Join-Path $RaulRoot "RAULMANUAL"
$StartupBatName = "Start_RAUL_Apps.bat"

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

function Assert-Admin {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run PowerShell as Administrator, then run this script again."
    }
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

function Update-RaulManualPort {
    param(
        [string]$ManualFolder,
        [int]$Port
    )

    $manualPy = Join-Path $ManualFolder "raul_manual.py"

    if (-not (Test-Path $manualPy)) {
        throw "Could not find raul_manual.py at $manualPy"
    }

    # Preserve UTF-8 as much as possible. This prevents rewriting the whole file with bad encoding.
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    $content = [System.IO.File]::ReadAllText($manualPy, [System.Text.Encoding]::UTF8)

    $pattern = 'app\.run\(host="0\.0\.0\.0",\s*port=\d+,\s*debug=True\)'
    $replacement = "app.run(host=""0.0.0.0"", port=$Port, debug=True)"

    $newContent = [regex]::Replace($content, $pattern, $replacement)

    if ($newContent -eq $content) {
        throw "Could not find this pattern in raul_manual.py: app.run(host=""0.0.0.0"", port=####, debug=True)"
    }

    [System.IO.File]::WriteAllText($manualPy, $newContent, $utf8NoBom)

    Write-OK "Updated RAULMANUAL port to $Port in raul_manual.py"
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

function Update-StartupBat {
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

    Write-OK "Updated startup file: $batPath"
}

function Rename-ThisComputer {
    param([string]$NewComputerName)

    if ([string]::IsNullOrWhiteSpace($NewComputerName)) {
        Write-Info "Computer name left unchanged."
        return $false
    }

    $NewComputerName = $NewComputerName.Trim()

    if ($NewComputerName -eq $env:COMPUTERNAME) {
        Write-Info "Computer name is already $NewComputerName"
        return $false
    }

    Rename-Computer -NewName $NewComputerName -Force
    Write-OK "Computer rename scheduled: $env:COMPUTERNAME -> $NewComputerName"
    return $true
}

# ---------------- MAIN ----------------

Assert-Admin

Write-Host ""
Write-Host "RAUL SETTINGS UPDATE" -ForegroundColor Cyan
Write-Host ""

if (-not (Test-Path $RaulRoot)) {
    Write-Warn "Default RAUL folder not found:"
    Write-Warn $RaulRoot
    $customRoot = Read-Host "Enter RAUL 2.0 folder path manually"

    if ([string]::IsNullOrWhiteSpace($customRoot) -or -not (Test-Path $customRoot)) {
        throw "Valid RAUL folder path was not provided."
    }

    $RaulRoot = $customRoot.Trim()
    $DashFolder = Join-Path $RaulRoot "RAULDASH"
    $ManualFolder = Join-Path $RaulRoot "RAULMANUAL"
}

Write-Info "RAUL folder: $RaulRoot"
Write-Host ""

$newComputerName = Read-Host "Enter new computer name, or press ENTER to keep $env:COMPUTERNAME"
$tabName = Read-Host "Enter LocationLog tab name"
$projectName = Read-Host "Enter ProjectName / Job name"
$portInput = Read-Host "Enter RAULMANUAL port, or press ENTER for 5000"

if ([string]::IsNullOrWhiteSpace($tabName)) {
    throw "LocationLog tab name cannot be blank."
}

if ([string]::IsNullOrWhiteSpace($projectName)) {
    throw "ProjectName / Job name cannot be blank."
}

if ([string]::IsNullOrWhiteSpace($portInput)) {
    $port = 5000
}
else {
    $port = [int]$portInput
}

if ($port -lt 1 -or $port -gt 65535) {
    throw "Invalid port number: $port"
}

Write-Host ""
Write-Info "Applying changes..."

$needsReboot = Rename-ThisComputer -NewComputerName $newComputerName

Update-SettingsXml -Folder $DashFolder -TabName $tabName.Trim() -ProjectName $projectName.Trim()
Update-SettingsXml -Folder $ManualFolder -TabName $tabName.Trim() -ProjectName $projectName.Trim()
Update-RaulConfig -ManualFolder $ManualFolder -TabName $tabName.Trim()
Update-RaulManualPort -ManualFolder $ManualFolder -Port $port
Update-FirewallForPort -Port $port
Update-StartupBat -DashFolder $DashFolder -ManualFolder $ManualFolder -Port $port

Write-Host ""
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "RAUL SETTINGS UPDATED" -ForegroundColor Green
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Computer name: $env:COMPUTERNAME"
if ($newComputerName -and $newComputerName -ne $env:COMPUTERNAME) {
    Write-Host "New computer name after reboot: $newComputerName"
}
Write-Host "LocationLog: $($tabName.Trim())!A:D"
Write-Host "ProjectName / Job name: $($projectName.Trim())"
Write-Host "RAULMANUAL local URL: http://127.0.0.1:$port"
Write-Host ""
Write-Host "For network access, use:"
Write-Host "http://THIS-COMPUTER-IP:$port"
Write-Host ""

if ($needsReboot) {
    Write-Warn "A reboot is required for the computer name change."
    $restart = Read-Host "Restart now? Y/N"

    if ($restart -match "^[Yy]") {
        Restart-Computer -Force
    }
}

Read-Host "Press ENTER to close"
