Write-Host "========================================================"
Write-Host "  PassWardN - Automated Build & Publish Script"
Write-Host "========================================================"
Write-Host ""

Write-Host "[1/3] Installing Dependencies via winget..."
# Install Rust / Cargo
Write-Host " -> Checking for Rustup..."
winget install -e --id Rustlang.Rustup --accept-source-agreements --accept-package-agreements

# Install Python (for the emergency extractor build script)
Write-Host " -> Checking for Python 3..."
winget install -e --id Python.Python.3 --accept-source-agreements --accept-package-agreements

Write-Host ""
Write-Host "[2/3] Refreshing Environment Variables..."
# Reload PATH so we can use cargo immediately without restarting the terminal
$env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")

Write-Host ""
Write-Host "[3/4] Terminating any running instances..."
taskkill /F /IM PassWardN.exe /T 2>$null

Write-Host ""
Write-Host "[4/4] Building Optimized Release Executable..."
cargo build --release

Write-Host ""
if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Build Successful!"
    Write-Host "   -> PassWardN.exe is located in: target\release\"
}
else {
    Write-Host "❌ Build Failed. Please check the error messages above."
    Write-Host "   (Note: If this is a fresh Rust install, you may need to install the 'C++ Build Tools' when prompted by rustup)."
    exit $LASTEXITCODE
}
