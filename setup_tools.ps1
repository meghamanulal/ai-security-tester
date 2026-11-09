# PowerShell script to install security scanning tools
Write-Host "Installing security scanning tools for AI Security Tester..." -ForegroundColor Green

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Please run this script as Administrator to install tools system-wide."
    Write-Host "Continuing with user-level installation where possible..." -ForegroundColor Yellow
}

# Install Chocolatey if not present
if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
    Write-Host "Installing Chocolatey package manager..." -ForegroundColor Yellow
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
}

# Install Nmap
Write-Host "Installing Nmap..." -ForegroundColor Yellow
choco install nmap -y

# Install Go for Subfinder and Nuclei
Write-Host "Installing Go..." -ForegroundColor Yellow
choco install golang -y

# Refresh PATH
$env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("PATH", "User")

# Install Go tools
Write-Host "Installing Subfinder..." -ForegroundColor Yellow
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

Write-Host "Installing Nuclei..." -ForegroundColor Yellow
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Install Nikto (requires Perl)
Write-Host "Installing Strawberry Perl (required for Nikto)..." -ForegroundColor Yellow
choco install strawberryperl -y

# Download Nikto
Write-Host "Downloading Nikto..." -ForegroundColor Yellow
if (-not (Test-Path "C:\tools\nikto")) {
    New-Item -ItemType Directory -Path "C:\tools\nikto" -Force
    Invoke-WebRequest -Uri "https://github.com/sullo/nikto/archive/master.zip" -OutFile "C:\tools\nikto\nikto.zip"
    Expand-Archive -Path "C:\tools\nikto\nikto.zip" -DestinationPath "C:\tools\nikto" -Force
    Move-Item -Path "C:\tools\nikto\nikto-master\program\nikto.pl" -Destination "C:\tools\nikto\nikto.pl" -Force
}

# Install Ruby for wpscan
Write-Host "Installing Ruby (required for wpscan)..." -ForegroundColor Yellow
choco install ruby -y

# Install wpscan gem
Write-Host "Installing wpscan..." -ForegroundColor Yellow
gem install wpscan

# Update Nuclei templates
Write-Host "Updating Nuclei templates..." -ForegroundColor Yellow
& "$env:USERPROFILE\go\bin\nuclei.exe" -update-templates

# Add tools to PATH
$toolsPath = @(
    "C:\Program Files (x86)\Nmap",
    "$env:USERPROFILE\go\bin",
    "C:\tools\nikto",
    "C:\Ruby25\bin"  # For wpscan if using Ruby
)

foreach ($path in $toolsPath) {
    if (-not ($env:PATH -like "*$path*")) {
        $env:PATH += ";$path"
        [System.Environment]::SetEnvironmentVariable("PATH", $env:PATH, "User")
    }
}

Write-Host "Installation complete!" -ForegroundColor Green
Write-Host "Please restart your terminal or PowerShell session to use the new tools." -ForegroundColor Yellow
Write-Host "You may need to add C:\tools\nikto to your PATH manually if nikto.pl is not found." -ForegroundColor Yellow

# Test installations
Write-Host "Testing tool installations..." -ForegroundColor Yellow

try {
    $nmapVersion = nmap --version
    Write-Host "✓ Nmap installed: $nmapVersion" -ForegroundColor Green
} catch {
    Write-Host "✗ Nmap not found in PATH" -ForegroundColor Red
}

try {
    $subfinderVersion = subfinder -version
    Write-Host "✓ Subfinder installed: $subfinderVersion" -ForegroundColor Green
} catch {
    Write-Host "✗ Subfinder not found in PATH" -ForegroundColor Red
}

try {
    $nucleiVersion = nuclei -version
    Write-Host "✓ Nuclei installed: $nucleiVersion" -ForegroundColor Green
} catch {
    Write-Host "✗ Nuclei not found in PATH" -ForegroundColor Red
}

try {
    $niktoVersion = perl "C:\tools\nikto\nikto.pl" -Version 2>$null
    Write-Host "✓ Nikto installed" -ForegroundColor Green
} catch {
    Write-Host "✗ Nikto not found or Perl not working" -ForegroundColor Red
}

try {
    $wpscanVersion = wpscan --version
    Write-Host "✓ WPScan installed: $wpscanVersion" -ForegroundColor Green
} catch {
    Write-Host "✗ WPScan not found in PATH" -ForegroundColor Red
}

Write-Host "Setup script completed. Check above for any errors." -ForegroundColor Cyan
