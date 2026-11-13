<#
.SYNOPSIS
    Installs Cyber Caffeine for the current user: Python (if missing), the pinned
    libraries, a start-at-sign-in shortcut, and starts the app.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\install.ps1
        Install and start, and start automatically at every sign-in.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\install.ps1 -NoStartup
        Install and start, but don't add the start-at-sign-in shortcut.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\install.ps1 -Uninstall
        Stop the app and remove the shortcut and notification registration.
        Your settings in %LOCALAPPDATA%\CyberCaffeine are kept; delete that folder too
        for a clean removal.

.NOTES
    No admin rights needed. Everything is per-user. Runs on Windows PowerShell 5.1.
#>
param(
    [switch]$NoStartup,
    [switch]$Uninstall,
    [string]$StartupFolder = [Environment]::GetFolderPath("Startup")
)

$ErrorActionPreference = "Stop"
$AppDir = $PSScriptRoot
$TrayApp = Join-Path $AppDir "tray_app.py"
$Shortcut = Join-Path $StartupFolder "Cyber Caffeine.lnk"
$AumidKey = "HKCU:\Software\Classes\AppUserModelId\Cyber Caffeine"

function Step($text) { Write-Host "==> $text" -ForegroundColor Cyan }

function Stop-App {
    Get-CimInstance Win32_Process -Filter "Name='pythonw.exe' OR Name='python.exe'" |
        Where-Object { $_.CommandLine -like "*tray_app.py*" } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -Confirm:$false; Write-Host "    stopped running copy (PID $($_.ProcessId))" }
}

function Find-Python {
    # Real installs only: skip the Microsoft Store "python.exe" stub in WindowsApps.
    $candidates = @()
    $py = Get-Command py -ErrorAction SilentlyContinue
    if ($py) {
        try { $candidates += (& $py.Source -3 -c "import sys; print(sys.executable)" 2>$null) } catch {}
    }
    $candidates += Get-ChildItem "$env:LOCALAPPDATA\Programs\Python\Python3*\python.exe", "$env:ProgramFiles\Python3*\python.exe" -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending | ForEach-Object FullName
    foreach ($exe in $candidates | Where-Object { $_ -and (Test-Path $_) }) {
        $ok = & $exe -c "import sys; print(sys.version_info >= (3, 10))" 2>$null
        if ($ok -eq "True") { return $exe }
    }
    return $null
}

if ($Uninstall) {
    Step "Removing Cyber Caffeine"
    Stop-App
    if (Test-Path $Shortcut) { Remove-Item $Shortcut -Force; Write-Host "    removed start-at-sign-in shortcut" }
    if (Test-Path $AumidKey) { Remove-Item $AumidKey -Recurse -Force; Write-Host "    removed notification registration" }
    Write-Host "Done. Settings kept in $env:LOCALAPPDATA\CyberCaffeine (delete it for a clean removal)."
    exit 0
}

if (-not (Test-Path $TrayApp)) { throw "tray_app.py not found next to this script ($AppDir)." }

Step "Checking for Python 3.10 or newer"
$python = Find-Python
if (-not $python) {
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        throw "Python not found and winget isn't available. Install Python 3.14 from python.org, then run this script again."
    }
    Write-Host "    not found: installing Python 3.14 with winget (current user only)"
    winget install --id Python.Python.3.14 --source winget --scope user --silent --accept-package-agreements --accept-source-agreements
    $python = Find-Python
    if (-not $python) { throw "Python installed but not found. Open a new PowerShell window and run this script again." }
}
Write-Host "    using $python"
$pythonw = Join-Path (Split-Path $python) "pythonw.exe"

Step "Installing pinned libraries (each download is checked against its fingerprint)"
# --require-hashes: refuse any file whose SHA-256 isn't listed in requirements.txt
# --only-binary:    ready-built packages only, never compile anything from source
& $python -m pip install --disable-pip-version-check --quiet --upgrade `
    --require-hashes --only-binary ":all:" -r (Join-Path $AppDir "requirements.txt")
if ($LASTEXITCODE -ne 0) { throw "pip install failed (exit $LASTEXITCODE)." }

Step "Stopping any copy that's already running"
Stop-App

if ($NoStartup) {
    Step "Skipping start-at-sign-in shortcut (-NoStartup)"
} else {
    Step "Adding start-at-sign-in shortcut"
    $shell = New-Object -ComObject WScript.Shell
    $lnk = $shell.CreateShortcut($Shortcut)
    $lnk.TargetPath = $pythonw
    $lnk.Arguments = "`"$TrayApp`""
    $lnk.WorkingDirectory = $AppDir
    $lnk.IconLocation = Join-Path $AppDir "assets\tray.ico"
    $lnk.Description = "Cyber Caffeine threat and outage notifications"
    $lnk.Save()
    Write-Host "    $Shortcut"
}

Step "Starting Cyber Caffeine"
Start-Process -FilePath $pythonw -ArgumentList "`"$TrayApp`"" -WorkingDirectory $AppDir
Write-Host ""
Write-Host "Installed. Look for the cup icon in the system tray (it may be under the ^ arrow)." -ForegroundColor Green
Write-Host "Settings: $env:LOCALAPPDATA\CyberCaffeine\config.json (Quit and restart the app after editing)."
