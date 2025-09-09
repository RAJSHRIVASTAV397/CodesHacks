# CodesHacks Installation Script for Windows

Write-Host "Installing CodesHacks dependencies..." -ForegroundColor Green

# Function to check if a command exists
function Test-Command($cmdname) {
    return [bool](Get-Command -Name $cmdname -ErrorAction SilentlyContinue)
}

# Install Chocolatey if not installed
if (-not (Test-Command "choco")) {
    Write-Host "Installing Chocolatey..." -ForegroundColor Green
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
}

# Install required packages using Chocolatey
Write-Host "Installing system packages..." -ForegroundColor Green
$packages = @(
    "python3"
    "golang"
    "nmap"
    "chromium"
    "chromedriver"
    "git"
)

foreach ($package in $packages) {
    Write-Host "Installing $package..." -ForegroundColor Cyan
    choco install $package -y
}

# Refresh environment variables
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

# Install Go tools
Write-Host "Installing Go tools..." -ForegroundColor Green
$gotools = @(
    "github.com/hahwul/dalfox/v2@latest"
    "github.com/ffuf/ffuf@latest"
    "github.com/OJ/gobuster@latest"
    "github.com/OWASP/Amass/v3/...@master"
)

foreach ($tool in $gotools) {
    Write-Host "Installing $tool..." -ForegroundColor Cyan
    go install $tool
}

# Install Python packages
Write-Host "Installing Python packages..." -ForegroundColor Green
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install selenium webdriver_manager dnspython requests bs4 aiohttp python-nmap wappalyzer

Write-Host "Installation completed!" -ForegroundColor Green
