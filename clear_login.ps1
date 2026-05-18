# PassWardN - Vault & Config Wipe Script
# Run this to completely clear the login and reset the application.

# 1. Kill the app if it's currently running so file locks are released!
Write-Host "🛑 Terminating PassWardN to release file locks..." -ForegroundColor Cyan
Stop-Process -Name "PassWardN" -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

$pathsToDelete = @(
    "$env:LOCALAPPDATA\Microsoft\Windows\WebCache\secure_vault.bin", # Primary Vault
    "$env:LOCALAPPDATA\Microsoft\Windows\WebCache\secure_vault.tmp",
    "$env:USERPROFILE\Documents\passwardvault_backup.bin",           # Backup Vault
    "$env:USERPROFILE\Documents\passwardvault_backup.tmp",
    "$PSScriptRoot\secure_vault.bin",                                # Root Portable Vault
    "$PSScriptRoot\target\debug\secure_vault.bin",                   # Cargo Debug Portable Vault
    "$PSScriptRoot\target\debug\secure_vault.tmp",
    "$PSScriptRoot\target\release\secure_vault.bin",                 # Cargo Release Portable Vault
    "$env:LOCALAPPDATA\Microsoft\Windows\WebCache\ghost_decoy.bin",  # Sparse Decoy File
    "$env:LOCALAPPDATA\PassWardN\config.bin",                        # Encrypted Config
    "$env:LOCALAPPDATA\PassWardN\config.json"                        # Legacy Config
)

Write-Host "🧹 Wiping PassWardN vaults and configurations..." -ForegroundColor Cyan

foreach ($path in $pathsToDelete) {
    if (Test-Path $path) {
        Remove-Item -Path $path -Force
        Write-Host "  [Deleted] $path" -ForegroundColor Green
    }
}

Write-Host "`n✅ PassWardN test ground is clean! The app will prompt for initialization on next launch." -ForegroundColor Yellow
