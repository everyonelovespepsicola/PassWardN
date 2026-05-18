# PassWardN - AI Context

## Project Overview
PassWardN is a highly secure, redundancy-focused password and file vault built in Rust. It features military-grade cryptography, a unique "Digital Dongle" MFA system, and a Redundancy Grid that automatically syncs encrypted vault chunks across multiple drives. 

## Key Technologies & Libraries
*   **Language:** Rust
*   **UI Framework:** `egui` (via `eframe`)
*   **Cryptography:** `chacha20poly1305`, `argon2`, `blake3`
*   **Filesystem & OS:** `notify` (for file watching), native Windows API (for virtual drive mounting via `subst` and NTFS sparse files)
*   **Serialization & Data:** `bincode` (binary efficiency), `serde`, `csv`
*   **Security:** Extensive use of the `zeroize` crate to clear plaintext passwords and cryptographic material from memory.

## Architecture Highlights
*   **Ghost Driver (Z:\ Mount):** A secure, temporary virtual drive designed to intercept and encrypt browser CSV exports natively. The background "Gobble" process watches this drive, encrypts the payload, and automatically shreds the plaintext file from the disk.
*   **Redundancy Grid:** Synchronizes the vault across Primary (Local AppData), Backup (Documents), and Portable (local executable directory) paths. Implements a consensus-based auto-heal mechanism to detect and repair corrupted or missing vaults.
*   **Digital Dongle (MFA):** Uses any ordinary file (image, text, mp3) as a hardware token by hashing its exact bit-for-bit contents using ultra-fast BLAKE3 to derive a secondary key slot.
*   **Decoys:** Generates massive 10GB sparse files filled with CSPRNG noise to misdirect adversaries or slow down ransomware operations.
*   **Zero-RAM File Storage:** Uses a chunked File Index architecture to encrypt and stream massive files directly to disk without causing excessive RAM consumption.

## Future Goals & Known Issues (from futuremanifest.txt)
*   **UI Enhancements:** 
    *   Organize the password view with adjustable, self-scaling columns.
    *   [X] Fix window scaling inconsistencies between the login screen and the decrypted vault view.
    *   Change the login screen theme to match the dark grey app theme instead of pure black.
    *   Implement password copying without visually revealing the password on screen.
*   **File Management:**
    *   Provide better UI feedback (progress bars, status updates) when mounting/unmounting drives and transferring large files.
    *   Build an internal file explorer to view and manage files inside the vault safely.
*   **Smart Data Ingestion:**
    *   When dropping a CSV file, make the app smart enough to update existing passwords instead of creating duplicates. Show a summary like "3 passwords updated, 10 ignored".
*   **Vault Portability:**
    *   Create a dedicated feature to move the entire vault to a new drive alongside the `.exe` so it can be used portably.
*   **UX Polish:**
    *   Update login text from "Enter Password OR drop a Dongle to unlock Vault & start Ghost Driver:" to "Enter Password OR drop a Dongle to unlock Vault:".
