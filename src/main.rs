#![windows_subsystem = "windows"]

use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};
use std::fs::OpenOptions;
use std::os::windows::io::AsRawHandle;
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::process::CommandExt;
use std::thread;
use std::sync::mpsc::channel;
use std::collections::HashSet;
use std::time::{Duration, Instant};
use std::io::{Read, Seek, SeekFrom, Write};
use zeroize::Zeroize;
use rand::{RngCore, thread_rng, Rng};
use eframe::egui;
use serde::{Deserialize, Serialize};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, aead::{Aead, KeyInit}};
use argon2::Argon2;

// Windows API constants for setting sparse files
const FSCTL_SET_SPARSE: u32 = 0x000900C4;

extern "system" {
    fn DeviceIoControl(
        hDevice: *mut std::ffi::c_void,
        dwIoControlCode: u32,
        lpInBuffer: *mut std::ffi::c_void,
        nInBufferSize: u32,
        lpOutBuffer: *mut std::ffi::c_void,
        nOutBufferSize: u32,
        lpBytesReturned: *mut u32,
        lpOverlapped: *mut std::ffi::c_void,
    ) -> i32;

    fn GetVolumeNameForVolumeMountPointW(
        lpszVolumeMountPoint: *const u16,
        lpszVolumeName: *mut u16,
        cchBufferLength: u32,
    ) -> i32;
}

fn current_date_string() -> String {
    // Use native Rust SystemTime instead of hooking OS DLLs directly
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(std::time::Duration::from_secs(0))
        .as_secs();

    let mut days = now / 86400;
    let mut year = 1970;
    loop {
        let leap = if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) { 366 } else { 365 };
        if days < leap { break; }
        days -= leap;
        year += 1;
    }
    let mut month = 1;
    let days_in_month = [
        31, if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) { 29 } else { 28 },
        31, 30, 31, 30, 31, 31, 30, 31, 30, 31
    ];
    for d in days_in_month.iter() {
        if days < *d { break; }
        days -= *d;
        month += 1;
    }
    let day = days + 1;
    let hours = (now / 3600) % 24;
    let mins = (now / 60) % 60;

    format!("{:04}-{:02}-{:02} {:02}:{:02} UTC", year, month, day, hours, mins)
}

const CREATE_NO_WINDOW: u32 = 0x08000000;

fn open_file_dialog() -> Option<PathBuf> {
    let output = std::process::Command::new("powershell")
        .creation_flags(CREATE_NO_WINDOW)
        .args([
            "-NoProfile",
            "-Command",
            r#"Add-Type -AssemblyName System.Windows.Forms; $dlg = New-Object System.Windows.Forms.OpenFileDialog; $dlg.Filter = 'CSV Files (*.csv)|*.csv|All Files (*.*)|*.*'; if ($dlg.ShowDialog() -eq 'OK') { Write-Output $dlg.FileName }"#
        ])
        .output()
        .ok()?;
    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if path.is_empty() {
        None
    } else {
        Some(PathBuf::from(path))
    }
}

fn open_directory_dialog() -> Option<PathBuf> {
    let output = std::process::Command::new("powershell")
        .creation_flags(CREATE_NO_WINDOW)
        .args([
            "-NoProfile",
            "-Command",
            r#"Add-Type -AssemblyName System.Windows.Forms; $dlg = New-Object System.Windows.Forms.FolderBrowserDialog; $dlg.Description = 'Select folder to dump vault contents'; if ($dlg.ShowDialog() -eq 'OK') { Write-Output $dlg.SelectedPath }"#
        ])
        .output()
        .ok()?;
    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if path.is_empty() { None } else { Some(PathBuf::from(path)) }
}

fn save_file_dialog(default_name: &str) -> Option<PathBuf> {
    let output = std::process::Command::new("powershell")
        .creation_flags(CREATE_NO_WINDOW)
        .args([
            "-NoProfile",
            "-Command",
            &format!(r#"Add-Type -AssemblyName System.Windows.Forms; $dlg = New-Object System.Windows.Forms.SaveFileDialog; $dlg.FileName = '{}'; $dlg.Filter = 'All Files (*.*)|*.*'; if ($dlg.ShowDialog() -eq 'OK') {{ Write-Output $dlg.FileName }}"#, default_name.replace("'", "''"))
        ])
        .output()
        .ok()?;
    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if path.is_empty() { None } else { Some(PathBuf::from(path)) }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PasswordEntry {
    #[serde(alias = "name", alias = "Name", alias = "Site")]
    name: Option<String>,
    #[serde(alias = "url", alias = "URL", alias = "Url", alias = "Address")]
    url: Option<String>,
    #[serde(alias = "username", alias = "Username", alias = "login", alias = "Login")]
    username: Option<String>,
    #[serde(alias = "password", alias = "Password", alias = "Secret")]
    password: Option<String>,
    #[serde(default)] // For backward compatibility with old vaults
    date: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub enum VaultItem {
    Credential(PasswordEntry),
    SecureFile {
        filename: String,
        file_size: u64,
        data: Vec<u8>,
    },
    FileIndex {
        filename: String,
        file_size: u64,
        #[serde(skip)]
        chunk_offset: u64,
    },
    SecureFileV2 {
        filename: String,
        file_size: u64,
        added_date: String,
        data: Vec<u8>,
    },
    FileIndexV2 {
        filename: String,
        file_size: u64,
        added_date: String,
        #[serde(skip)]
        chunk_offset: u64,
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ConfigEntry {
    original: PathBuf,
    guid: Option<String>,
}

fn config_path() -> PathBuf {
    if let Ok(appdata) = std::env::var("LOCALAPPDATA") {
        let mut p = PathBuf::from(appdata);
        p.push(r"PassWardN\config.bin");
        p
    } else {
        PathBuf::from("config.bin")
    }
}

fn load_custom_paths() -> Vec<PathBuf> {
    let path = config_path();
    let old_path = path.with_extension("json");

    // Seamlessly migrate an existing unencrypted config to the new binary format
    if old_path.exists() {
        if let Ok(data) = std::fs::read_to_string(&old_path) {
            if let Ok(paths) = serde_json::from_str::<Vec<PathBuf>>(&data) {
                let _ = std::fs::remove_file(&old_path);
                save_custom_paths(&paths);
                return paths;
            }
        }
    }

    if let Ok(mut file) = std::fs::File::open(&path) {
        let mut nonce_bytes = [0u8; 12];
        if file.read_exact(&mut nonce_bytes).is_ok() {
            let mut ciphertext = Vec::new();
            if file.read_to_end(&mut ciphertext).is_ok() {
                let key = Key::from_slice(b"PassWardN_Config_Obfuscation_Key");
                let cipher = ChaCha20Poly1305::new(key);
                let nonce = Nonce::from_slice(&nonce_bytes);
                if let Ok(plaintext) = cipher.decrypt(nonce, ciphertext.as_ref()) {
                    if let Ok(entries) = serde_json::from_slice::<Vec<ConfigEntry>>(&plaintext) {
                        return entries.into_iter().map(|e| e.original).collect();
                    }
                    if let Ok(paths) = serde_json::from_slice::<Vec<PathBuf>>(&plaintext) {
                        return paths;
                    }
                }
            }
        }
    }
    Vec::new()
}

fn get_volume_guid_for_path(path: &Path) -> Option<String> {
    let path_str = path.to_string_lossy();
    if path_str.len() >= 2 && path_str.chars().nth(1) == Some(':') {
        let drive = format!("{}\\", &path_str[0..2]);
        let drive_w: Vec<u16> = std::ffi::OsStr::new(&drive).encode_wide().chain(std::iter::once(0)).collect();
        let mut volume_name = [0u16; 100];
        let success = unsafe {
            GetVolumeNameForVolumeMountPointW(
                drive_w.as_ptr(),
                volume_name.as_mut_ptr(),
                volume_name.len() as u32,
            )
        };
        if success != 0 {
            let len = volume_name.iter().position(|&c| c == 0).unwrap_or(volume_name.len());
            return Some(String::from_utf16_lossy(&volume_name[..len]));
        }
    }
    None
}

fn save_custom_paths(paths: &[PathBuf]) {
    if let Some(parent) = config_path().parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let entries: Vec<ConfigEntry> = paths.iter().map(|p| ConfigEntry {
        original: p.clone(),
        guid: get_volume_guid_for_path(p),
    }).collect();

    if let Ok(data) = serde_json::to_vec(&entries) {
        let key = Key::from_slice(b"PassWardN_Config_Obfuscation_Key");
        let cipher = ChaCha20Poly1305::new(key);
        let mut nonce_bytes = [0u8; 12];
        thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        if let Ok(ciphertext) = cipher.encrypt(nonce, data.as_ref()) {
            if let Ok(mut file) = std::fs::File::create(config_path()) {
                let _ = file.write_all(&nonce_bytes);
                let _ = file.write_all(&ciphertext);
            }
        }
    }
}

fn resolve_drive_letters(paths: &mut Vec<PathBuf>) -> bool {
    let mut changed = false;

    let mut saved_entries: Vec<ConfigEntry> = Vec::new();
    if let Ok(mut file) = std::fs::File::open(config_path()) {
        let mut nonce_bytes = [0u8; 12];
        if file.read_exact(&mut nonce_bytes).is_ok() {
            let mut ciphertext = Vec::new();
            if file.read_to_end(&mut ciphertext).is_ok() {
                let key = Key::from_slice(b"PassWardN_Config_Obfuscation_Key");
                let cipher = ChaCha20Poly1305::new(key);
                let nonce = Nonce::from_slice(&nonce_bytes);
                if let Ok(plaintext) = cipher.decrypt(nonce, ciphertext.as_ref()) {
                    if let Ok(entries) = serde_json::from_slice::<Vec<ConfigEntry>>(&plaintext) {
                        saved_entries = entries;
                    }
                }
            }
        }
    }

    for path in paths.iter_mut() {
        if !path.exists() && path.is_absolute() {
            let path_str = path.to_string_lossy().to_string();
            if path_str.len() >= 3 && path_str.chars().nth(1) == Some(':') {
                let tail = &path_str[3..];
                let mut found = false;

                if let Some(expected_guid) = saved_entries.iter().find(|e| e.original == *path).and_then(|e| e.guid.clone()) {
                    for drive in b'A'..=b'Z' {
                        let test_drive = format!("{}:\\", drive as char);
                        if let Some(current_guid) = get_volume_guid_for_path(Path::new(&test_drive)) {
                            if current_guid == expected_guid {
                                let test_path = PathBuf::from(format!("{}:\\{}", drive as char, tail));
                                if test_path.exists() {
                                    *path = test_path;
                                    changed = true;
                                    found = true;
                                    break;
                                }
                            }
                        }
                    }

                    if !found {
                        let guid_path = PathBuf::from(format!("{}{}", expected_guid, tail));
                        if guid_path.exists() {
                            *path = guid_path;
                            changed = true;
                            found = true;
                        }
                    }
                }

                if !found {
                    for drive in b'A'..=b'Z' {
                        let test_path = PathBuf::from(format!("{}:\\{}", drive as char, tail));
                        if test_path.exists() {
                            if let Ok(mut file) = std::fs::File::open(&test_path) {
                                let mut magic = [0u8; 4];
                                if file.read_exact(&mut magic).is_ok() && &magic == b"GVLT" {
                                    *path = test_path;
                                    changed = true;
                                    break;
                                }
                            }
                        }
                    }
                }
            } else if path_str.starts_with(r"\\?\Volume{") {
                if let Some(idx) = path_str.find("}\\") {
                    let guid = &path_str[..idx + 2];
                    let tail = &path_str[idx + 2..];
                    for drive in b'A'..=b'Z' {
                        let test_drive = format!("{}:\\", drive as char);
                        if let Some(current_guid) = get_volume_guid_for_path(Path::new(&test_drive)) {
                            if current_guid == guid {
                                let test_path = PathBuf::from(format!("{}:\\{}", drive as char, tail));
                                if test_path.exists() {
                                    *path = test_path;
                                    changed = true;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    changed
}

/// Returns the Redundancy Grid paths (Primary, Backup, Portable)
fn get_vault_paths() -> Vec<PathBuf> {
    let mut custom = load_custom_paths();
    if !custom.is_empty() {
        if resolve_drive_letters(&mut custom) {
            save_custom_paths(&custom);
        }
        return custom;
    }

    let mut paths = Vec::new();

    // 1. Primary: Stealth folder in Local AppData
    if let Ok(appdata) = std::env::var("LOCALAPPDATA") {
        let mut p = PathBuf::from(appdata);
        p.push(r"Microsoft\Windows\WebCache\secure_vault.bin");
        paths.push(p);
    }

    // 2. Secondary: Backup in Documents
    if let Ok(userprofile) = std::env::var("USERPROFILE") {
        let mut p = PathBuf::from(userprofile);
        p.push(r"Documents\passwardvault_backup.bin");
        paths.push(p);
    }

    // 3. Portable: USB/Local (Next to the executable itself)
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(parent) = exe_path.parent() {
            paths.push(parent.join("secure_vault.bin"));
        }
    }

    paths.sort();
    paths.dedup(); // Remove duplicates (e.g., if you ran the .exe from Documents)
    paths
}

fn derive_kek(material: &[u8], salt: &[u8; 16]) -> [u8; 32] {
    let mut kek = [0u8; 32];
    let _ = Argon2::default().hash_password_into(material, salt, &mut kek);
    kek
}

fn derive_recovery_kek(a1: &str, a2: &str, a3: &str, salt: &[u8; 16]) -> [u8; 32] {
    let combined = format!("{}-{}-{}", a1.trim().to_lowercase(), a2.trim().to_lowercase(), a3.trim().to_lowercase());
    derive_kek(combined.as_bytes(), salt)
}

fn encrypt_slot(kek: &[u8; 32], master_key: &[u8; 32]) -> [u8; 60] {
    let key = Key::from_slice(kek);
    let cipher = ChaCha20Poly1305::new(key);
    let mut nonce_bytes = [0u8; 12];
    thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, master_key.as_ref()).unwrap_or_default();
    let mut slot = [0u8; 60];
    slot[0..12].copy_from_slice(&nonce_bytes);
    let len = std::cmp::min(ciphertext.len(), 48);
    slot[12..12 + len].copy_from_slice(&ciphertext[..len]);
    slot
}

fn decrypt_slot(kek: &[u8; 32], slot: &[u8; 60]) -> Option<[u8; 32]> {
    let nonce = Nonce::from_slice(&slot[0..12]);
    let ciphertext = &slot[12..60];
    let key = Key::from_slice(kek);
    let cipher = ChaCha20Poly1305::new(key);
    if let Ok(pt) = cipher.decrypt(nonce, ciphertext) {
        if pt.len() == 32 {
            let mut master_key = [0u8; 32];
            master_key.copy_from_slice(&pt);
            return Some(master_key);
        }
    }
    None
}

/// Reads the CSV from disk, parses it into memory, and returns the records.
fn ingest_csv(file: &std::fs::File) -> Result<Vec<VaultItem>, Box<dyn std::error::Error>> {
    let mut file_clone = file.try_clone()?;
    file_clone.seek(SeekFrom::Start(0))?;
    let mut rdr = csv::ReaderBuilder::new()
        .flexible(true) // Accommodate varying row formats
        .has_headers(false) // We manually check for headers so we don't drop data
        .from_reader(file_clone);

    let mut record = csv::StringRecord::new();
    if !rdr.read_record(&mut record)? {
        return Ok(Vec::new());
    }
    let first_row = record.clone();

    let mut url_idx = None;
    let mut username_idx = None;
    let mut password_idx = None;
    let mut name_idx = None;

    let mut unmapped_indices = Vec::new();
    let mut is_header = false;

    // Map headers dynamically so we never leave any info behind
    for (i, h) in first_row.iter().enumerate() {
        let hl = h.to_lowercase();
        if url_idx.is_none() && (hl.contains("url") || hl.contains("website") || hl.contains("host") || hl.contains("address")) {
            url_idx = Some(i);
            is_header = true;
        } else if username_idx.is_none() && (hl.contains("user") || hl.contains("login") || hl.contains("email")) {
            username_idx = Some(i);
            is_header = true;
        } else if password_idx.is_none() && (hl.contains("pass") || hl.contains("secret")) {
            password_idx = Some(i);
            is_header = true;
        } else if name_idx.is_none() && (hl.contains("name") || hl.contains("site") || hl.contains("title") || hl.contains("app")) {
            name_idx = Some(i);
            is_header = true;
        } else {
            unmapped_indices.push(i);
        }
    }

    let mut headers = None;

    if is_header {
        // Save the header row so we can label extra_info fields
        headers = Some(first_row.clone());
    } else {
        // First row is pure data. Fallback to generic positional mapping.
        url_idx = if first_row.len() > 0 { Some(0) } else { None };
        username_idx = if first_row.len() > 1 { Some(1) } else { None };
        password_idx = if first_row.len() > 2 { Some(2) } else { None };
        name_idx = if first_row.len() > 3 { Some(3) } else { None };

        unmapped_indices.clear();
        for i in 4..first_row.len() {
            unmapped_indices.push(i);
        }
    }

    let mut entries = Vec::new();

    let mut process_record = |rec: &csv::StringRecord| {
        let url = url_idx.and_then(|i| rec.get(i)).unwrap_or("").to_string();
        let username = username_idx.and_then(|i| rec.get(i)).unwrap_or("").to_string();
        let password = password_idx.and_then(|i| rec.get(i)).unwrap_or("").to_string();
        let mut name = name_idx.and_then(|i| rec.get(i)).unwrap_or("").to_string();

        let mut extra_info = Vec::new();
        for &i in &unmapped_indices {
            if let Some(v) = rec.get(i) {
                if !v.is_empty() {
                    let h_name = if let Some(ref h) = headers {
                        h.get(i).unwrap_or("Unknown")
                    } else {
                        "Unknown"
                    };
                    extra_info.push(format!("{}: {}", h_name, v));
                }
            }
        }

        if !extra_info.is_empty() {
            let combined_extra = extra_info.join(" | ");
            name = if name.is_empty() { combined_extra } else { format!("{} | {}", name, combined_extra) };
        }

        if url.is_empty() && username.is_empty() && password.is_empty() && name.is_empty() { return; }

        entries.push(VaultItem::Credential(PasswordEntry {
            name: if name.is_empty() { None } else { Some(name) },
            url: if url.is_empty() { None } else { Some(url) },
            username: if username.is_empty() { None } else { Some(username) },
            password: if password.is_empty() { None } else { Some(password) },
            date: Some(current_date_string()),
        }));
    };

    // If the first row wasn't a header, it's our first credential to process
    if !is_header {
        process_record(&first_row);
    }

    // Process the rest of the file
    while rdr.read_record(&mut record)? {
        process_record(&record);
    }

    Ok(entries)
}

/// Secures the parsed passwords by encrypting them with ChaCha20-Poly1305 and appending to the vault.
fn encrypt_and_store(entries: &[VaultItem], vault_paths: &[PathBuf], master_key: &[u8; 32], log: &mut impl FnMut(String)) -> Result<(), Box<dyn std::error::Error>> {
    log("  -> Serializing data using Bincode for binary efficiency...".to_string());
    let serialized_data = bincode::serialize(entries)?;

    log("  -> Initializing ChaCha20-Poly1305 with Argon2 derived key...".to_string());
    let key = Key::from_slice(master_key);
    let cipher = ChaCha20Poly1305::new(key);

    let mut nonce_bytes = [0u8; 12];
    thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    log("  -> Encrypting payload with military-grade cryptography...".to_string());
    let ciphertext = cipher.encrypt(nonce, serialized_data.as_ref())
        .map_err(|e| format!("Encryption failure: {:?}", e))?;

    log("  -> Appending encrypted data to Redundancy Grid...".to_string());
    let len = ciphertext.len() as u32;

    for path in vault_paths {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match OpenOptions::new().write(true).create(true).append(true).open(path) {
            Ok(mut file) => {
                let _ = file.write_all(&len.to_le_bytes());
                let _ = file.write_all(&nonce_bytes);
                let _ = file.write_all(&ciphertext);
                log(format!("     * Synced chunk to: {:?}", path));
            }
            Err(e) => log(format!("     ⚠ Failed to sync to {:?}: {}", path, e)),
        }
    }

    log("  -> Vault grid safely secured.".to_string());
    Ok(())
}

/// Reads and decrypts the entire vault from disk
fn decrypt_vault(vault_path: &Path, master_key: &[u8; 32]) -> Result<Vec<VaultItem>, Box<dyn std::error::Error>> {
    let mut file = std::fs::File::open(vault_path)?;
    let key = Key::from_slice(master_key);
    let cipher = ChaCha20Poly1305::new(key);

    let mut all_entries: Vec<VaultItem> = Vec::new();

    // Detect header version to skip correctly
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic)?;
    let header_size = if &magic == b"GVL2" { 200 } else { 140 };

    file.seek(SeekFrom::Start(header_size))?;

    loop {
        // 1. Read the chunk length prefix
        let mut len_buf = [0u8; 4];
        match file.read_exact(&mut len_buf) {
            Ok(_) => {},
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                break;
            },
            Err(e) => return Err(e.into()),
        }
        let chunk_len = u32::from_le_bytes(len_buf) as usize;

        // Sanity check: Increased to 2GB to allow storing massive files natively without triggering a false corruption error.
        if chunk_len > 2_000_000_000 { // 2 GB max per chunk
            return Err("Vault corruption detected! Chunk size exceeds 2GB maximum.".into());
        }

        // 2. Read the Nonce
        let mut nonce_buf = [0u8; 12];
        if let Err(e) = file.read_exact(&mut nonce_buf) {
            return Err(format!("Failed to read nonce (corrupted vault): {}", e).into());
        }
        let nonce = Nonce::from_slice(&nonce_buf);

        // 3. Read the Ciphertext
        let mut ct_buf = vec![0u8; chunk_len];
        if let Err(e) = file.read_exact(&mut ct_buf) {
            return Err(format!("Failed to read ciphertext (corrupted vault): {}", e).into());
        }

        // 4. Decrypt and Parse
        let pt = cipher.decrypt(nonce, ct_buf.as_ref())
            .map_err(|e| format!("Decryption failure: {:?}", e))?;

        // Try Bincode first, fall back to JSON if it fails (for backwards compatibility with old vaults)
        let mut entries: Vec<VaultItem> = match bincode::deserialize(&pt) {
            Ok(items) => items,
            Err(_) => {
                let old_entries: Vec<PasswordEntry> = serde_json::from_slice(&pt)?;
                old_entries.into_iter().map(VaultItem::Credential).collect()
            }
        };

        let mut has_file_index = false;
        for entry in &mut entries {
            match entry {
                VaultItem::FileIndex { ref mut chunk_offset, .. } |
                VaultItem::FileIndexV2 { ref mut chunk_offset, .. } => {
                    *chunk_offset = file.stream_position().unwrap_or(0); // Capture the offset of the next chunk!
                    has_file_index = true;
                }
                _ => {}
            }
        }

        all_entries.append(&mut entries);

        if has_file_index {
            // The very next chunk is the raw 2GB payload. Skip reading it into RAM!
            let mut p_len_buf = [0u8; 4];
            if file.read_exact(&mut p_len_buf).is_ok() {
                let p_len = u32::from_le_bytes(p_len_buf);
                let _ = file.seek(SeekFrom::Current(12 + p_len as i64)); // Skip Nonce + Ciphertext
            }
        }
    }

    Ok(all_entries)
}

/// Safely repackages the vault by streaming valid items to temporary files and replacing the old vaults.
fn repack_vault(
    entries: &mut Vec<VaultItem>,
    active_vault_path: &Path,
    vault_paths: &[PathBuf],
    master_key: &[u8; 32],
    new_header: Option<Vec<u8>>,
    log: &mut impl FnMut(String)
) -> Result<(), Box<dyn std::error::Error>> {
    log("📦 Repacking vault to reclaim space and finalize modifications...".to_string());
    let mut old_file = std::fs::File::open(active_vault_path)?;

    let header = match new_header {
        Some(h) => h,
        None => {
            let mut magic = [0u8; 4];
            old_file.read_exact(&mut magic)?;
            old_file.seek(SeekFrom::Start(0))?;
            let header_size = if &magic == b"GVL2" { 200 } else { 140 };
            let mut h = vec![0u8; header_size];
            old_file.read_exact(&mut h)?;
            if header_size == 140 {
                let mut upgraded = vec![0u8; 200];
                upgraded[0..4].copy_from_slice(b"GVL2");
                upgraded[4..140].copy_from_slice(&h[4..140]);
                upgraded
            } else {
                h
            }
        }
    };

    let tmp_paths: Vec<PathBuf> = vault_paths.iter().map(|p| p.with_extension("tmp")).collect();

    // Init tmp files with header
    for tmp in &tmp_paths {
        if let Some(p) = tmp.parent() { let _ = std::fs::create_dir_all(p); }
        let mut f = OpenOptions::new().write(true).create(true).truncate(true).open(tmp)?;
        f.write_all(&header)?;
    }

    for entry in entries.iter_mut() {
        match entry {
            VaultItem::Credential(_) | VaultItem::SecureFile { .. } | VaultItem::SecureFileV2 { .. } => {
                encrypt_and_store(&[entry.clone()], &tmp_paths, master_key, log)?;
            },
            VaultItem::FileIndex { .. } | VaultItem::FileIndexV2 { .. } => {
                let (idx_item, orig_offset) = match entry {
                    VaultItem::FileIndex { filename, file_size, chunk_offset } => (VaultItem::FileIndex { filename: filename.clone(), file_size: *file_size, chunk_offset: 0 }, *chunk_offset),
                    VaultItem::FileIndexV2 { filename, file_size, added_date, chunk_offset } => (VaultItem::FileIndexV2 { filename: filename.clone(), file_size: *file_size, added_date: added_date.clone(), chunk_offset: 0 }, *chunk_offset),
                    _ => unreachable!(),
                };
                encrypt_and_store(&[idx_item], &tmp_paths, master_key, log)?;

                old_file.seek(SeekFrom::Start(orig_offset))?;
                let mut len_buf = [0u8; 4];
                old_file.read_exact(&mut len_buf)?;
                let chunk_len = u32::from_le_bytes(len_buf) as usize;

                let mut nonce_buf = [0u8; 12];
                old_file.read_exact(&mut nonce_buf)?;

                let mut new_offset = 0;

                for tmp in &tmp_paths {
                    let mut f = OpenOptions::new().write(true).append(true).open(tmp)?;
                    f.write_all(&len_buf)?;
                    f.write_all(&nonce_buf)?;

                    old_file.seek(SeekFrom::Start(orig_offset + 4 + 12))?;
                    let mut reader = std::io::Read::by_ref(&mut old_file).take(chunk_len as u64);
                    std::io::copy(&mut reader, &mut f)?;

                    if new_offset == 0 {
                        new_offset = std::fs::metadata(tmp).map(|m| m.len() - (4 + 12 + chunk_len as u64)).unwrap_or(0);
                    }
                }
                match entry {
                    VaultItem::FileIndex { ref mut chunk_offset, .. } => *chunk_offset = new_offset,
                    VaultItem::FileIndexV2 { ref mut chunk_offset, .. } => *chunk_offset = new_offset,
                    _ => unreachable!(),
                }
            }
        }
    }

    drop(old_file);

    for (i, path) in vault_paths.iter().enumerate() {
        let tmp = &tmp_paths[i];
        if tmp.exists() {
            let _ = std::fs::rename(tmp, path);
        }
    }

    log("✅ Vault repacked successfully.".to_string());
    Ok(())
}

/// Answers the Manifest's Decoy Request: Creates a zero-allocated sparse file on Windows
fn create_sparse_decoy(path: &Path, logical_size_bytes: u64) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(path)?;

    let handle = file.as_raw_handle();
    let mut bytes_returned = 0;

    // 1. Mark the file as sparse in NTFS
    let success = unsafe {
        DeviceIoControl(
            handle,
            FSCTL_SET_SPARSE,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            0,
            &mut bytes_returned,
            std::ptr::null_mut(),
        )
    };

    if success == 0 {
        return Err(std::io::Error::last_os_error());
    }

    // 2. Set the logical end of the file (creates the massive apparent size with 0 bytes on disk)
    file.set_len(logical_size_bytes)?;

    // Write chunks of CSPRNG (random) data to random offsets so the sparse file
    // isn't just empty zeros, mimicking the high entropy of a ChaCha20 encrypted vault.
    let mut rng = thread_rng();
    let mut buffer = vec![0u8; 1024 * 1024]; // 1MB chunks

    // Write 50 random 1MB chunks spread across the 10GB file
    for _ in 0..50 {
        rng.fill_bytes(&mut buffer);
        let random_offset = rng.gen_range(0..logical_size_bytes - buffer.len() as u64);
        file.seek(SeekFrom::Start(random_offset))?;
        file.write_all(&buffer)?;
    }

    println!("Decoy created successfully at {:?}", path);
    Ok(())
}

/// Attempts to open a file with Read/Write privileges.
/// Loops and waits if the file is currently locked by the OS or a downloading browser.
fn wait_for_access(path: &Path) -> std::io::Result<std::fs::File> {
    let mut attempts = 0;
    loop {
        match OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(1) // 1 = FILE_SHARE_READ (Allows AV to peek, breaking deadlocks, but denies write access)
            .open(path) {
            Ok(file) => return Ok(file),
            Err(e) => {
                if attempts > 30 {
                    return Err(e); // Give up after 3 seconds of trying
                }
                thread::sleep(Duration::from_millis(100));
                attempts += 1;
            }
        }
    }
}

/// Securely shreds the file by overwriting it with zeros before unlinking it from the filesystem
fn shred_file(mut file: std::fs::File, path: &Path, log: &mut impl FnMut(String)) -> std::io::Result<()> {
    let len = file.metadata()?.len();
    log(format!("  -> Shredding {} bytes...", len));
    file.seek(SeekFrom::Start(0))?;

    // Create a 4KB chunk of memory filled with 0xFF
    let mut buffer = vec![0xFF; 4096];

    let mut written = 0;
    while written < len {
        let chunk = std::cmp::min(len - written, buffer.len() as u64) as usize;
        file.write_all(&buffer[..chunk])?;
        written += chunk as u64;
    }

    // Zeroize the RAM buffer now that we are done with it
    buffer.zeroize();

    log("  -> Forcing hardware sync...".to_string());
    // Force the OS to flush the 0xFF overwrites down to the physical drive hardware
    file.sync_all()?;

    log("  -> Releasing file lock...".to_string());
    // Release our lock on the file so the OS lets us delete it
    drop(file);

    log("  -> Evading AV and deleting...".to_string());
    // Windows Defender often swoops in the microsecond we close the file to scan it,
    // locking us out from deleting it. We retry the delete for up to 1 second.
    let mut delete_attempts = 0;
    while let Err(e) = std::fs::remove_file(path) {
        if e.kind() == std::io::ErrorKind::NotFound {
            break; // File is already gone!
        }
        if delete_attempts > 30 {
            return Err(e);
        }
        thread::sleep(Duration::from_millis(100));
        delete_attempts += 1;
    }
    Ok(())
}

/// Provisions a Secure Temp Folder natively
fn setup_drop_zone(log: &mut impl FnMut(String)) -> PathBuf {
    let fallback = std::env::temp_dir().join("GhostDropZone");
    let _ = std::fs::create_dir_all(&fallback);
    log(format!("  -> Clean Room active at {:?}", fallback));
    fallback
}

/// Maps the Z: drive to the Drop Zone
fn mount_z_drive(log: &mut impl FnMut(String)) -> bool {
    let fallback = std::env::temp_dir().join("GhostDropZone");
    log("  -> Attempting to mount native Virtual Drive (Z:)...".to_string());
    let output = std::process::Command::new("subst")
        .args(["Z:", fallback.to_str().unwrap_or_default()])
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    if let Ok(out) = output {
        if out.status.success() {
            log("  -> Virtual Drop Zone successfully mounted at Z:\\".to_string());
            return true;
        } else {
            log("  -> ⚠ Failed to mount Z:\\ (Drive letter might be in use)".to_string());
        }
    }
    false
}

/// Unmaps the Z: drive
fn unmount_z_drive(log: &mut impl FnMut(String)) {
    log("  -> Unmounting Virtual Drive (Z:)...".to_string());
    let _ = std::process::Command::new("subst")
        .args(["/D", "Z:"])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
}

/// Incinerates the Temp folder and ensures Z: is unmapped
fn teardown_drop_zone(log: &mut impl FnMut(String)) {
    unmount_z_drive(log);
    log("  -> Incinerating Clean Room...".to_string());

    let fallback = std::env::temp_dir().join("GhostDropZone");
    if fallback.exists() {
        let _ = std::fs::remove_dir_all(&fallback);
    }
}

/// "The Gobble": Watches the RAM disk for the CSV payload
fn start_the_gobble(ram_drive_path: &Path, shared_key: std::sync::Arc<std::sync::Mutex<[u8; 32]>>, log_tx: std::sync::mpsc::Sender<String>, entries_tx: std::sync::mpsc::Sender<Vec<VaultItem>>, ctx: egui::Context, import_mode: std::sync::Arc<std::sync::atomic::AtomicBool>) -> notify::Result<()> {
    let (tx, rx) = channel();

    let mut log = |msg: String| {
        println!("{}", msg);
        let _ = log_tx.send(msg);
        ctx.request_repaint();
    };

    // Set up the watcher with a delay to mitigate partial-write race conditions
    let config = Config::default().with_poll_interval(Duration::from_millis(250));
    let mut watcher = RecommendedWatcher::new(tx, config)?;

    watcher.watch(ram_drive_path, RecursiveMode::NonRecursive)?;
    log(format!("👁 Ghost Driver is watching RAM Drive at {:?}", ram_drive_path));

    for res in rx {
        match res {
            Ok(Event { paths, .. }) => {
                for file_path in paths {
                    // Stop The Gobble from eating anything if the user has it in safe Export Mode
                    if !import_mode.load(std::sync::atomic::Ordering::SeqCst) {
                        continue;
                    }

                    // If the file was already shredded by a previous event, skip it
                    if !file_path.exists() {
                        continue;
                    }

                    // We only target CSVs (case insensitive check)
                    let is_csv = file_path
                        .extension()
                        .map_or(false, |ext| ext.eq_ignore_ascii_case("csv"));

                    if !is_csv {
                        continue;
                    }

                    // Prevent The Gobble from eating our own exported dumps!
                    if let Some(file_name) = file_path.file_name() {
                        if file_name.to_string_lossy().eq_ignore_ascii_case("passwords_export.csv") {
                            continue;
                        }
                    }

                    // Skip zero-byte files that just started downloading or copying
                    if let Ok(meta) = file_path.metadata() {
                        if meta.len() == 0 {
                            continue;
                        }
                    }

                    log(format!("🚨 Gobble triggered for: {:?}", file_path));

                    // Wait for the browser/OS to finish saving the file
                    match wait_for_access(&file_path) {
                        Ok(file) => {
                            log(format!("✅ File lock acquired! Ready to shred: {:?}", file_path));

                            // INGESTION PHASE
                            log("  -> Ingesting CSV payload into memory...".to_string());
                            match ingest_csv(&file) {
                                Ok(entries) => {
                                    log(format!("  -> Successfully parsed {} password entries!", entries.len()));
                                    for entry in &entries {
                                            if let VaultItem::Credential(c) = entry {
                                                if let Some(site) = &c.url {
                                                    log(format!("     * Captured credentials for: {}", site));
                                                }
                                        }
                                    }
                                    let vault_paths = get_vault_paths();
                                    let current_key = *shared_key.lock().unwrap();
                                    if let Err(e) = encrypt_and_store(&entries, &vault_paths, &current_key, &mut log) {
                                        log(format!("  -> ⚠ Vault encryption failed: {}", e));
                                    } else {
                                        let _ = entries_tx.send(entries.clone());
                                    }
                                },
                                Err(e) => log(format!("  -> ⚠ Failed to ingest CSV: {}", e)),
                            }

                            if let Err(e) = shred_file(file, &file_path, &mut log) {
                                log(format!("❌ Failed to shred {:?}: {}", file_path, e));
                            } else {
                                log("🗑  Successfully shredded and removed!".to_string());
                            }
                        },
                        Err(e) => log(format!("⚠ Could not acquire lock (still downloading?): {}", e)),
                    }
                }
            },
            Err(e) => log(format!("Watch error: {:?}", e)),
        }
    }
    Ok(())
}

#[derive(PartialEq)]
enum CredentialChangeMode {
    ChangePassword,
    ChangeDongle,
    ManageLocations,
    ChangeRecovery,
}

struct UnlockSuccess {
    entries: Vec<VaultItem>,
    master_key: [u8; 32],
    dongle_hash: Option<[u8; 32]>,
}

struct PasswordVaultApp {
    log_rx: std::sync::mpsc::Receiver<String>,
    log_tx: std::sync::mpsc::Sender<String>,
    entries_rx: std::sync::mpsc::Receiver<Vec<VaultItem>>,
    entries_tx: std::sync::mpsc::Sender<Vec<VaultItem>>,
    vault_paths: Vec<PathBuf>,
    staged_vault_paths: Vec<PathBuf>,
    shared_key: std::sync::Arc<std::sync::Mutex<[u8; 32]>>,
    ghost_driver_running: bool,
    logs: Vec<String>,
    is_unlocked: bool,
    password_input: String,
    decrypted_entries: Vec<VaultItem>,
    show_close_warning: bool,
    dropped_file_path: Option<PathBuf>,
    dropped_vault_path: Option<PathBuf>,
    show_change_credentials_modal: bool,
    credential_change_mode: CredentialChangeMode,
    old_password_input: String,
    new_password_input: String,
    new_dropped_file_path: Option<PathBuf>,
    active_drop_zone: Option<PathBuf>,
    z_drive_mounted: bool,
    revealed_passwords: HashSet<usize>,
    active_dongle_hash: Option<[u8; 32]>,
    is_mounting: bool,
    is_unmounting: bool,
    mount_progress: f32,
    mount_rx: Option<std::sync::mpsc::Receiver<bool>>,
    unmount_rx: Option<std::sync::mpsc::Receiver<()>>,
    remove_dongle_staged: bool,
    last_activity: Instant,
    is_decrypting: bool,
    unlock_rx: Option<std::sync::mpsc::Receiver<Result<UnlockSuccess, String>>>,
    item_to_delete: Option<usize>,
    is_repacking: bool,
    repack_rx: Option<std::sync::mpsc::Receiver<Vec<VaultItem>>>,

    is_importing_file: bool,
    import_file_name: String,
    import_progress: f32,
    import_status: String,
    import_finished: bool,
    import_rx: Option<std::sync::mpsc::Receiver<(f32, String, bool)>>,
    show_sync_results_modal: bool,
    sync_results_message: String,
    show_dump_modal: bool,
    import_mode: std::sync::Arc<std::sync::atomic::AtomicBool>,
    show_z_mount_modal: bool,
    show_grid_heal_modal: bool,
    show_delete_all_modal: bool,
    delete_all_password_input: String,
    show_add_password_modal: bool,
    add_password_url: String,
    add_password_username: String,
    add_password_password: String,
    add_password_show_password: bool,
    add_password_gen_length: usize,
    add_password_gen_numbers: bool,
    add_password_gen_symbols: bool,
    add_password_gen_mixed_case: bool,
    failed_login_attempts: usize,
    show_recovery_modal: bool,
    show_setup_recovery_modal: bool,
    setup_a1: String,
    setup_a2: String,
    setup_a3: String,
    recovery_a1: String,
    recovery_a2: String,
    recovery_a3: String,
    change_recovery_a1: String,
    change_recovery_a2: String,
    change_recovery_a3: String,
    login_generated_password: String,
}

impl PasswordVaultApp {
    fn new(log_tx: std::sync::mpsc::Sender<String>, log_rx: std::sync::mpsc::Receiver<String>, entries_tx: std::sync::mpsc::Sender<Vec<VaultItem>>, entries_rx: std::sync::mpsc::Receiver<Vec<VaultItem>>) -> Self {
        Self {
            log_rx,
            log_tx,
            entries_rx,
            entries_tx,
            vault_paths: get_vault_paths(),
            staged_vault_paths: Vec::new(),
            shared_key: std::sync::Arc::new(std::sync::Mutex::new([0u8; 32])),
            ghost_driver_running: false,
            logs: Vec::new(),
            is_unlocked: false,
            password_input: String::new(),
            decrypted_entries: Vec::new(),
            show_close_warning: false,
            dropped_file_path: None,
            dropped_vault_path: None,
            show_change_credentials_modal: false,
            credential_change_mode: CredentialChangeMode::ChangePassword,
            old_password_input: String::new(),
            new_password_input: String::new(),
            new_dropped_file_path: None,
            active_drop_zone: None,
            z_drive_mounted: false,
            revealed_passwords: HashSet::new(),
            active_dongle_hash: None,
            is_mounting: false,
            is_unmounting: false,
            mount_progress: 0.0,
            mount_rx: None,
            unmount_rx: None,
            remove_dongle_staged: false,
            last_activity: Instant::now(),
            is_decrypting: false,
            unlock_rx: None,
            item_to_delete: None,
            is_repacking: false,
            repack_rx: None,

            is_importing_file: false,
            import_file_name: String::new(),
            import_progress: 0.0,
            import_status: String::new(),
            import_finished: false,
            import_rx: None,
            show_sync_results_modal: false,
            sync_results_message: String::new(),
            show_dump_modal: false,
            import_mode: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            show_z_mount_modal: false,
            show_grid_heal_modal: false,
            show_delete_all_modal: false,
            delete_all_password_input: String::new(),
            show_add_password_modal: false,
            add_password_url: String::new(),
            add_password_username: String::new(),
            add_password_password: String::new(),
            add_password_show_password: false,
            add_password_gen_length: 12,
            add_password_gen_numbers: true,
            add_password_gen_symbols: true,
            add_password_gen_mixed_case: true,
            failed_login_attempts: 0,
            show_recovery_modal: false,
            show_setup_recovery_modal: false,
            setup_a1: String::new(),
            setup_a2: String::new(),
            setup_a3: String::new(),
            recovery_a1: String::new(),
            recovery_a2: String::new(),
            recovery_a3: String::new(),
            change_recovery_a1: String::new(),
            change_recovery_a2: String::new(),
            change_recovery_a3: String::new(),
            login_generated_password: String::new(),
        }
    }

    fn import_csv(&mut self, path: PathBuf, ctx: egui::Context) {
        self.logs.push(format!("📥 Importing CSV from {:?}", path));
        let tx = self.entries_tx.clone();
        let log_tx = self.log_tx.clone();
        let current_key = *self.shared_key.lock().unwrap();

        std::thread::spawn(move || {
            let mut log = |msg: String| {
                let _ = log_tx.send(msg);
                ctx.request_repaint();
            };
            match std::fs::File::open(&path) {
                Ok(file) => {
                    match ingest_csv(&file) {
                        Ok(entries) => {
                            let vault_paths = get_vault_paths();
                            if let Err(e) = encrypt_and_store(&entries, &vault_paths, &current_key, &mut log) {
                                log(format!("  -> ⚠ Vault encryption failed: {}", e));
                            } else {
                                let _ = tx.send(entries.clone());
                                log(format!("✅ Successfully imported {} passwords!", entries.len()));
                            }
                        }
                        Err(e) => log(format!("⚠ Failed to parse CSV: {}", e)),
                    }
                }
                Err(e) => log(format!("⚠ Failed to open file: {}", e)),
            }
        });
    }

    fn import_secure_file(&mut self, path: PathBuf, ctx: egui::Context) {
        let filename = path.file_name().unwrap_or_default().to_string_lossy().into_owned();
        self.logs.push(format!("📥 Capturing secure file from {:?}", path));

        self.is_importing_file = true;
        self.import_file_name = filename.clone();
        self.import_progress = 0.0;
        self.import_status = "Starting...".to_string();
        self.import_finished = false;

        let (status_tx, status_rx) = std::sync::mpsc::channel();
        self.import_rx = Some(status_rx);

        let tx = self.entries_tx.clone();
        let log_tx = self.log_tx.clone();
        let current_key = *self.shared_key.lock().unwrap();

        std::thread::spawn(move || {
            let mut log = |msg: String| {
                let _ = log_tx.send(msg);
                ctx.request_repaint();
            };

            let _ = status_tx.send((0.0, "Reading file...".to_string(), false));
            ctx.request_repaint();

            match std::fs::File::open(&path) {
                Ok(mut file) => {
                    let file_size = file.metadata().map(|m| m.len()).unwrap_or(0);
                    let mut data = Vec::with_capacity(file_size as usize);
                    let mut buffer = vec![0u8; 1024 * 1024 * 4]; // 4MB buffer on the Heap (prevents Stack Overflow)
                    let mut bytes_read = 0;

                    let mut last_update = Instant::now();

                    loop {
                        match file.read(&mut buffer) {
                            Ok(0) => break,
                            Ok(n) => {
                                data.extend_from_slice(&buffer[..n]);
                                bytes_read += n as u64;

                                if last_update.elapsed().as_millis() > 50 {
                                    let progress = if file_size > 0 {
                                        (bytes_read as f32 / file_size as f32) * 0.3
                                    } else { 0.0 };
                                    let _ = status_tx.send((progress, "Reading file into memory...".to_string(), false));
                                    ctx.request_repaint();
                                    last_update = Instant::now();
                                }
                            }
                            Err(e) => {
                                log(format!("⚠ Failed to read file: {}", e));
                                let _ = status_tx.send((0.0, format!("Error: {}", e), true));
                                ctx.request_repaint();
                                return;
                            }
                        }
                    }

                    // 1. Create the lightweight index item
                    let item = VaultItem::FileIndexV2 { filename: filename.clone(), file_size, added_date: current_date_string(), chunk_offset: 0 };
                    let vault_paths = get_vault_paths();

                    let _ = status_tx.send((0.3, "Securing Metadata...".to_string(), false));
                    ctx.request_repaint();

                    // 2. Encrypt and store the tiny FileIndex chunk
                    if let Err(e) = encrypt_and_store(&[item.clone()], &vault_paths, &current_key, &mut log) {
                        log(format!("  -> ⚠ Vault encryption failed: {}", e));
                        let _ = status_tx.send((0.0, "Encryption failed".to_string(), true));
                        ctx.request_repaint();
                        return;
                    }

                    let _ = status_tx.send((0.4, "Encrypting large payload (this may take a moment)...".to_string(), false));
                    ctx.request_repaint();

                    // 3. Encrypt and append the massive RAW payload chunk directly
                    log("  -> Encrypting massive payload safely to disk...".to_string());
                    let key = Key::from_slice(&current_key);
                    let cipher = ChaCha20Poly1305::new(key);
                    let mut nonce_bytes = [0u8; 12];
                    thread_rng().fill_bytes(&mut nonce_bytes);
                    let nonce = Nonce::from_slice(&nonce_bytes);

                    let ciphertext = match cipher.encrypt(nonce, data.as_ref()) {
                        Ok(ct) => ct,
                        Err(e) => {
                            log(format!("Encryption failure: {:?}", e));
                            let _ = status_tx.send((0.0, "Encryption failed".to_string(), true));
                            ctx.request_repaint();
                            return;
                        }
                    };

                    let _ = status_tx.send((0.8, "Writing to disk...".to_string(), false));
                    ctx.request_repaint();

                    let len = ciphertext.len() as u32;
                    for p in &vault_paths {
                        if let Ok(mut file) = OpenOptions::new().write(true).append(true).open(p) {
                            let _ = file.write_all(&len.to_le_bytes());
                            let _ = file.write_all(&nonce_bytes);

                            // Chunked write for smooth UI updates
                            let mut written = 0;
                            let chunk_sz = 1024 * 1024 * 4; // 4MB
                            while written < ciphertext.len() {
                                let end = std::cmp::min(written + chunk_sz, ciphertext.len());
                                let _ = file.write_all(&ciphertext[written..end]);
                                written = end;

                                if last_update.elapsed().as_millis() > 50 {
                                    let w_prog = 0.8 + (0.19 * (written as f32 / ciphertext.len() as f32));
                                    let _ = status_tx.send((w_prog, "Writing to vault...".to_string(), false));
                                    ctx.request_repaint();
                                    last_update = Instant::now();
                                }
                            }
                        }
                    }

                    // Grab the absolute disk offset of where we just placed the raw chunk
                    let chunk_offset = std::fs::metadata(&vault_paths[0]).map(|m| m.len() - (4 + 12 + ciphertext.len() as u64)).unwrap_or(0);
                    let mut final_item = item;
                    match &mut final_item {
                        VaultItem::FileIndex { chunk_offset: ref mut c_offset, .. } |
                        VaultItem::FileIndexV2 { chunk_offset: ref mut c_offset, .. } => {
                            *c_offset = chunk_offset;
                        }
                        _ => {}
                    }

                    let _ = tx.send(vec![final_item]);
                    log("✅ Successfully captured large file via zero-RAM Metadata Index!".to_string());

                    let _ = status_tx.send((1.0, format!("✅ {} secured successfully!", filename), true));
                    ctx.request_repaint();
                }
                Err(e) => {
                    log(format!("⚠ Failed to open file: {}", e));
                    let _ = status_tx.send((0.0, format!("Error: {}", e), true));
                    ctx.request_repaint();
                }
            }
        });
    }

    fn execute_dump(&mut self, ctx: egui::Context, dump_csv: bool, dump_files: bool) {
        let msg = match (dump_csv, dump_files) {
            (true, true) => "💥 Initiating Full Dump (Files & CSV)...",
            (true, false) => "💥 Initiating CSV Dump...",
            (false, true) => "💥 Initiating File Dump...",
            (false, false) => return,
        };
        self.logs.push(msg.to_string());

        let has_files = dump_files && self.decrypted_entries.iter().any(|item| matches!(item, VaultItem::SecureFile{..} | VaultItem::SecureFileV2{..} | VaultItem::FileIndex{..} | VaultItem::FileIndexV2{..}));
        let has_passwords = dump_csv && self.decrypted_entries.iter().any(|item| matches!(item, VaultItem::Credential(_)));

        if dump_csv && !has_passwords {
            self.logs.push("⚠ No passwords found to dump.".to_string());
            return;
        }
        if dump_files && !has_files {
            self.logs.push("⚠ No files found to dump.".to_string());
            return;
        }

        let mut dump_dir = None;

        // Prompt the user for a physical hard drive folder if they have files or passwords to dump!
        if has_files || has_passwords {
            match open_directory_dialog() {
                Some(mut dir) => {
                    dir.push("PassWardN_Dump"); // Create a neat subfolder in the chosen directory
                    dump_dir = Some(dir);
                },
                None => {
                    self.logs.push("Dump cancelled by user.".to_string());
                    return;
                }
            }
        }

        let entries = self.decrypted_entries.clone();
        let log_tx = self.log_tx.clone();
        let mk_clone = *self.shared_key.lock().unwrap();

        std::thread::spawn(move || {
            let log = |msg: String| {
                let _ = log_tx.send(msg);
                ctx.request_repaint();
            };

            let mut passwords = Vec::new();
            let mut file_count = 0;

            if let Some(ref d_dir) = dump_dir {
                if let Err(e) = std::fs::create_dir_all(d_dir) {
                    log(format!("❌ Failed to create dump directory: {}", e));
                    return;
                }
                if dump_files {
                    log(format!("📂 Dumping stored files to {:?}", d_dir));
                }
            }

            for item in entries {
                match item {
                    VaultItem::Credential(c) => {
                        if dump_csv { passwords.push(c); }
                    }
                            VaultItem::SecureFile { filename, data, .. } |
                            VaultItem::SecureFileV2 { filename, data, .. } => {
                        if dump_files {
                            if let Some(ref d_dir) = dump_dir {
                                if let Err(e) = std::fs::write(d_dir.join(&filename), data) {
                                    log(format!("  -> ⚠ Failed to write {}: {}", filename, e));
                                } else {
                                    file_count += 1;
                                }
                            }
                        }
                    }
                            VaultItem::FileIndex { filename, chunk_offset, .. } |
                            VaultItem::FileIndexV2 { filename, chunk_offset, .. } => {
                        if dump_files {
                            if let Some(ref d_dir) = dump_dir {
                                let target_vault = get_vault_paths().into_iter().find(|p| p.exists()).unwrap();
                                if let Ok(mut file) = std::fs::File::open(target_vault) {
                                    if file.seek(SeekFrom::Start(chunk_offset)).is_ok() {
                                    let mut len_buf = [0u8; 4];
                                    if file.read_exact(&mut len_buf).is_ok() {
                                        let chunk_len = u32::from_le_bytes(len_buf) as usize;
                                        let mut nonce_buf = [0u8; 12];
                                        if file.read_exact(&mut nonce_buf).is_ok() {
                                            let mut ct_buf = vec![0u8; chunk_len];
                                            if file.read_exact(&mut ct_buf).is_ok() {
                                                let key = Key::from_slice(&mk_clone);
                                                let cipher = ChaCha20Poly1305::new(key);
                                                let nonce = Nonce::from_slice(&nonce_buf);
                                                if let Ok(pt) = cipher.decrypt(nonce, ct_buf.as_ref()) {
                                                    if let Err(e) = std::fs::write(d_dir.join(&filename), pt) {
                                                        log(format!("  -> ⚠ Failed to extract {}: {}", filename, e));
                                                    } else {
                                                        file_count += 1;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            }

            if !passwords.is_empty() {
                // A temporary struct strictly for formatting the CSV output safely for browsers
                #[derive(Serialize)]
                struct StandardCsvEntry<'a> {
                    name: &'a Option<String>,
                    url: &'a Option<String>,
                    username: &'a Option<String>,
                    password: &'a Option<String>,
                }

                let csv_dir = if let Some(ref d_dir) = dump_dir {
                    d_dir.clone()
                } else {
                    log("  -> ⚠ Cannot dump CSV: No folder selected.".to_string());
                    return;
                };

                match csv::Writer::from_path(csv_dir.join("passwords_export.csv")) {
                    Ok(mut wtr) => {
                        let mut success = true;
                        for p in &passwords {
                            let export_row = StandardCsvEntry {
                                name: &p.name,
                                url: &p.url,
                                username: &p.username,
                                password: &p.password,
                            };
                            if let Err(e) = wtr.serialize(&export_row) {
                                log(format!("  -> ⚠ Failed to write password row: {}", e));
                                success = false;
                            }
                        }
                        let _ = wtr.flush();
                        if success {
                            log(format!("✅ Dumped {} passwords to passwords_export.csv", passwords.len()));
                        }
                    }
                    Err(e) => log(format!("  -> ❌ Failed to create passwords_export.csv: {}", e)),
                }
            }
            if dump_csv {
                log(format!("✅ Dump complete. Extracted {} passwords to disk.", passwords.len()));
            }
            if dump_files {
                log(format!("✅ Dump complete. Extracted {} files to disk.", file_count));
            }
        });
    }

    fn execute_repack(&mut self, ctx: egui::Context, new_header: Option<Vec<u8>>) {
        self.is_repacking = true;
        let mut entries = self.decrypted_entries.clone();
        let master_key = *self.shared_key.lock().unwrap();
        let log_tx = self.log_tx.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        self.repack_rx = Some(rx);

        std::thread::spawn(move || {
            let mut log = |msg: String| {
                let _ = log_tx.send(msg);
                ctx.request_repaint();
            };

            let vault_paths = get_vault_paths();
            let active_vault = vault_paths.iter().find(|p| p.exists()).cloned().unwrap_or_else(|| vault_paths[0].clone());

            if let Err(e) = repack_vault(&mut entries, &active_vault, &vault_paths, &master_key, new_header, &mut log) {
                log(format!("❌ Repack failed: {}", e));
            }

            let _ = tx.send(entries);
            ctx.request_repaint();
        });
    }
}

impl eframe::App for PasswordVaultApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Track user activity (mouse movement, clicks, or keystrokes)
        if ctx.input(|i| !i.events.is_empty() || i.pointer.is_moving()) {
            self.last_activity = Instant::now();
        }

        // Idle Auto-Lock: Secure the vault if inactive for 60 seconds (120 if Z: drive is mounted)
        let timeout_secs = if self.z_drive_mounted { 120 } else { 60 };
        if self.is_unlocked && self.last_activity.elapsed().as_secs() > timeout_secs {
            self.is_unlocked = false;
            if let Some(pos) = ctx.input(|i| i.viewport().outer_rect).map(|r| r.min) {
                ctx.send_viewport_cmd(egui::ViewportCommand::OuterPosition(egui::pos2(pos.x + 325.0, pos.y + 50.0)));
            }
            ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(550.0, 500.0)));
            self.revealed_passwords.clear();
            self.decrypted_entries.clear();
            self.ghost_driver_running = false;
            self.z_drive_mounted = false;
            self.old_password_input.zeroize();
            self.old_password_input.clear();
            self.new_password_input.zeroize();
            self.new_password_input.clear();
            self.active_dongle_hash = None;
            self.dropped_vault_path = None;
            self.dropped_file_path = None;
            self.remove_dongle_staged = false;
            self.is_repacking = false;
            self.item_to_delete = None;
            self.is_importing_file = false;
            self.import_rx = None;
            self.show_sync_results_modal = false;
            self.show_dump_modal = false;
            self.show_z_mount_modal = false;
            self.show_grid_heal_modal = false;
            self.show_delete_all_modal = false;
            self.delete_all_password_input.zeroize();
            self.delete_all_password_input.clear();
            let mut local_logs = Vec::new();
            self.failed_login_attempts = 0;
            self.show_recovery_modal = false;
            self.show_setup_recovery_modal = false;
            self.recovery_a1.clear();
            self.recovery_a2.clear();
            self.recovery_a3.clear();
            teardown_drop_zone(&mut |msg| local_logs.push(msg));
            self.logs.extend(local_logs);
            self.active_drop_zone = None;
            self.logs.push(format!("🔒 Vault automatically locked due to {} seconds of inactivity.", timeout_secs));
        }

        // Force the UI thread to wake up every second while unlocked so the timer can trigger even if the mouse is perfectly still
        if self.is_unlocked {
            ctx.request_repaint_after(Duration::from_secs(1));
        }

        // Handle mount task completion
        if let Some(rx) = &self.mount_rx {
            if let Ok(success) = rx.try_recv() {
                self.is_mounting = false;
                self.z_drive_mounted = success;
                self.mount_rx = None;
            } else {
                self.mount_progress += 0.05; // Fake progress while waiting
                if self.mount_progress > 1.0 { self.mount_progress = 0.0; }
                ctx.request_repaint(); // Keep UI animating smoothly
            }
        }

        // Handle unmount task completion
        if let Some(rx) = &self.unmount_rx {
            if let Ok(_) = rx.try_recv() {
                self.is_unmounting = false;
                self.z_drive_mounted = false;
                self.unmount_rx = None;
            } else {
                self.mount_progress += 0.05;
                if self.mount_progress > 1.0 { self.mount_progress = 0.0; }
                ctx.request_repaint();
            }
        }

        // Handle unlock task completion
        if let Some(rx) = &self.unlock_rx {
            if let Ok(result) = rx.try_recv() {
                self.is_decrypting = false;
                self.unlock_rx = None;
                match result {
                    Ok(success) => {
                        self.is_unlocked = true;
                        if let Some(pos) = ctx.input(|i| i.viewport().outer_rect).map(|r| r.min) {
                            ctx.send_viewport_cmd(egui::ViewportCommand::OuterPosition(egui::pos2(pos.x - 325.0, pos.y - 50.0)));
                        }
                        ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(1200.0, 600.0)));
                        self.active_dongle_hash = success.dongle_hash;
                        self.decrypted_entries = success.entries;
                        self.logs.push("✅ Vault Unlocked. Derived ChaCha20 key via Argon2.".to_string());
                        self.logs.push(format!("🔓 Successfully decrypted {} items from vault.", self.decrypted_entries.len()));
                        if self.dropped_vault_path.is_some() {
                            self.logs.push("ℹ Force-loaded vault active. Future saves will sync to the Redundancy Grid.".to_string());
                        }
                        self.dropped_vault_path = None;
                        self.dropped_file_path = None;

                        {
                            let mut key_lock = self.shared_key.lock().unwrap();
                            *key_lock = success.master_key;
                        }

                        // Auto-Heal: Check if any Redundancy Grid locations are missing, corrupted, or desynced
                        let mut needs_healing = false;
                        let mut size_counts = std::collections::HashMap::new();
                        for path in &self.vault_paths {
                            let len = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
                            if len >= 140 {
                                *size_counts.entry(len).or_insert(0) += 1;
                            }
                        }
                        let mut consensus_size = 0;
                        let mut max_count = 0;
                        for (&size, &count) in &size_counts {
                            if count > max_count || (count == max_count && size > consensus_size) {
                                max_count = count;
                                consensus_size = size;
                            }
                        }

                        for path in &self.vault_paths {
                            let len = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
                            if !path.exists() || len < 140 || len != consensus_size {
                                needs_healing = true;
                                break;
                            }
                        }
                        if needs_healing {
                            self.logs.push("🩹 Grid degradation or desync detected! Auto-reconstructing missing/outdated vaults...".to_string());
                            self.show_grid_heal_modal = true;
                            self.execute_repack(ctx.clone(), None);
                        }

                        if !self.ghost_driver_running {
                            self.ghost_driver_running = true;
                            let mut local_logs = Vec::new();
                            let drop_zone = setup_drop_zone(&mut |msg| local_logs.push(msg));
                            self.logs.extend(local_logs);
                            self.active_drop_zone = Some(drop_zone.clone());

                            let ctx_clone = ctx.clone();
                            let tx_clone = self.log_tx.clone();
                            let entries_tx_clone = self.entries_tx.clone();
                            let shared_key_clone = self.shared_key.clone();
                            let import_mode_clone = self.import_mode.clone();
                            std::thread::spawn(move || {
                                if drop_zone.exists() {
                                    if let Err(e) = start_the_gobble(&drop_zone, shared_key_clone, tx_clone, entries_tx_clone, ctx_clone, import_mode_clone) {
                                        println!("❌ Ghost Driver crashed: {}", e);
                                    }
                                } else {
                                    println!("Drop zone not mounted. Awaiting Ghost Driver init...");
                                }
                            });
                        }
                    }
                    Err(e) => {
                        self.logs.push(format!("❌ Failed to decrypt vault: {}", e));
                        self.is_unlocked = false;
                    }
                }
            }
        }

        // Intercept the window close event if the vault is currently unlocked
        if ctx.input(|i| i.viewport().close_requested()) {
            if self.is_unlocked {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                self.show_close_warning = true;
            }
        }

        // Render the warning modal if triggered
        if self.show_close_warning {
            egui::Window::new("⚠ Warning")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.label("Your vault is still open!\nWould you like to lock and save your vault before closing?");
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        if ui.button("Lock & Close").clicked() {
                            self.is_unlocked = false;
                            self.revealed_passwords.clear();
                            self.decrypted_entries.clear();
                            self.z_drive_mounted = false;
                            self.old_password_input.zeroize();
                            self.old_password_input.clear();
                            self.new_password_input.zeroize();
                            self.new_password_input.clear();
                            self.active_dongle_hash = None;
                            self.dropped_vault_path = None;
                            self.dropped_file_path = None;
                            self.remove_dongle_staged = false;
                            self.is_repacking = false;
                            self.item_to_delete = None;
                            self.is_importing_file = false;
                            self.import_rx = None;
                            self.show_sync_results_modal = false;
                            self.show_dump_modal = false;
                            self.show_z_mount_modal = false;
                            self.show_grid_heal_modal = false;
                            self.show_delete_all_modal = false;
                            self.delete_all_password_input.zeroize();
                            self.delete_all_password_input.clear();
                            self.login_generated_password.zeroize();
                            self.login_generated_password.clear();
                            self.failed_login_attempts = 0;
                            self.show_recovery_modal = false;
                            self.recovery_a1.clear();
                            self.recovery_a2.clear();
                            self.recovery_a3.clear();
            self.change_recovery_a1.clear();
            self.change_recovery_a2.clear();
            self.change_recovery_a3.clear();
                            self.change_recovery_a1.clear();
                            self.change_recovery_a2.clear();
                            self.change_recovery_a3.clear();
                                        self.change_recovery_a1.clear();
                                        self.change_recovery_a2.clear();
                                        self.change_recovery_a3.clear();
                            let mut local_logs = Vec::new();
                            teardown_drop_zone(&mut |msg| local_logs.push(msg));
                            self.logs.extend(local_logs);
                            self.active_drop_zone = None;
                            self.show_close_warning = false;
                            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                        }
                        if ui.button("Cancel").clicked() {
                            self.show_close_warning = false;
                        }
                    });
                });
        }

        // Capture drag-and-dropped files for the Digital Dongle or CSV Imports
        let mut dropped_csv = None;
        let mut dropped_file_to_store = None;
        ctx.input(|i| {
            for file in &i.raw.dropped_files {
                if let Some(path) = &file.path {
                    if self.show_change_credentials_modal {
                        self.new_dropped_file_path = Some(path.clone());
                        self.logs.push(format!("🔑 New Digital Dongle staged: {:?}", path.file_name().unwrap_or_default()));
                    } else if !self.is_unlocked {
                        let is_vault = if let Ok(mut f) = std::fs::File::open(path) {
                            let mut magic = [0u8; 4];
                            f.read_exact(&mut magic).is_ok() && &magic == b"GVLT"
                        } else { false };
                        if is_vault {
                            self.dropped_vault_path = Some(path.clone());
                            self.logs.push(format!("📦 Vault staged for force load: {:?}", path.file_name().unwrap_or_default()));
                        } else {
                            self.dropped_file_path = Some(path.clone());
                            self.logs.push(format!("🔑 Digital Dongle staged: {:?}", path.file_name().unwrap_or_default()));
                        }
                    } else {
                        if path.extension().map_or(false, |ext| ext.eq_ignore_ascii_case("csv")) {
                            dropped_csv = Some(path.clone());
                        } else {
                            dropped_file_to_store = Some(path.clone());
                        }
                    }
                    break; // Just take the first dropped file
                }
            }
        });

        if !self.is_importing_file {
            if let Some(csv_path) = dropped_csv {
                self.import_csv(csv_path, ctx.clone());
            }
            if let Some(file_path) = dropped_file_to_store {
                self.import_secure_file(file_path, ctx.clone());
            }
        }

        while let Ok(msg) = self.log_rx.try_recv() {
            self.logs.push(msg);
        }

        while let Ok(new_entries) = self.entries_rx.try_recv() {
            let mut added = 0;
            let mut updated = 0;
            let mut ignored = 0;
            let mut needs_repack = false;

            for item in new_entries {
                match item {
                    VaultItem::Credential(mut new_cred) => {
                        let mut found = false;
                        for existing_item in &mut self.decrypted_entries {
                            if let VaultItem::Credential(existing_cred) = existing_item {
                                // Match entries cleanly based on identical URL and Username combinations
                                if new_cred.url == existing_cred.url && new_cred.username == existing_cred.username {
                                    found = true;
                                    if new_cred.password != existing_cred.password {
                                        existing_cred.password = new_cred.password.clone();
                                        existing_cred.date = Some(current_date_string());
                                        updated += 1;
                                        needs_repack = true; // Flag the vault to be securely repacked
                                    } else {
                                        ignored += 1;
                                    }
                                    break;
                                }
                            }
                        }
                        if !found {
                            new_cred.date = Some(current_date_string());
                            self.decrypted_entries.push(VaultItem::Credential(new_cred));
                            added += 1;
                            needs_repack = true;
                        }
                    },
                    item => self.decrypted_entries.push(item), // Safely push files without triggering repack
                }
            }

            if added > 0 || updated > 0 || ignored > 0 {
                let msg = format!("🔄 Smart Sync: {} added, {} updated, {} ignored.", added, updated, ignored);
                self.logs.push(msg.clone());
                self.sync_results_message = msg;
                self.show_sync_results_modal = true;
            }
            if needs_repack {
                self.execute_repack(ctx.clone(), None);
            }
        }

        if let Some(rx) = &self.repack_rx {
            if let Ok(updated_entries) = rx.try_recv() {
                self.decrypted_entries = updated_entries;
                self.is_repacking = false;
                self.repack_rx = None;
            }
        }

        // Handle import progress
        if let Some(rx) = &self.import_rx {
            while let Ok((prog, stat, fin)) = rx.try_recv() {
                self.import_progress = prog;
                self.import_status = stat;
                self.import_finished = fin;
            }
        }

        // Show the progress bar modal
        if self.is_mounting || self.is_unmounting {
            let title = if self.is_mounting { "⚙ Mounting Vault Z:\\..." } else { "⏏ Unmounting Vault Z:\\..." };
            egui::Window::new(title)
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.label("Please wait while the secure volume is configured.");
                    ui.add_space(10.0);
                    let progress_text = format!("{:.0}%", self.mount_progress * 100.0);
                    ui.add(egui::ProgressBar::new(self.mount_progress).animate(true).text(progress_text));
                });
        }

        if self.is_decrypting {
            egui::Window::new("⏳ Unlocking Vault...")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.label("Verifying cryptographic proofs and reading Metadata Index...");
                    ui.add_space(10.0);
                    ui.spinner();
                });
        }

        if self.is_repacking {
            egui::Window::new("📦 Repacking Vault...")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.label("Processing modifications and securing data...");
                    ui.add_space(10.0);
                    ui.spinner();
                });
        }

        if self.show_sync_results_modal {
            egui::Window::new("Smart Sync Results")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.label(&self.sync_results_message);
                    ui.add_space(10.0);
                    ui.vertical_centered(|ui| {
                        if ui.button("OK").clicked() {
                            self.show_sync_results_modal = false;
                        }
                    });
                });
        }

        if self.show_dump_modal {
            egui::Window::new("💥 Select Dump Type")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.label("What would you like to extract from the vault?");
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        if ui.button("📄 Passwords (CSV)").clicked() {
                            self.show_dump_modal = false;
                            self.execute_dump(ctx.clone(), true, false);
                        }
                        if ui.button("📁 Stored Files").clicked() {
                            self.show_dump_modal = false;
                            self.execute_dump(ctx.clone(), false, true);
                        }
                        if ui.button("❌ Cancel").clicked() {
                            self.show_dump_modal = false;
                        }
                    });
                });
        }

        if self.show_grid_heal_modal {
            egui::Window::new("🩹 Grid Degradation Auto-Heal")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.label("One or more vaults in your redundancy grid were missing, corrupted, or out-of-sync!");
                    ui.label("PassWardN has automatically started reconstructing them to restore full redundancy.");
                    ui.add_space(10.0);
                    ui.vertical_centered(|ui| {
                        if ui.button("OK").clicked() {
                            self.show_grid_heal_modal = false;
                        }
                    });
                });
        }

        if self.show_add_password_modal {
            egui::Window::new("➕ Add New Password")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    egui::Grid::new("add_password_grid").num_columns(2).spacing([10.0, 10.0]).show(ui, |ui| {
                        ui.label("URL / Site:");
                        ui.add(egui::TextEdit::singleline(&mut self.add_password_url));
                        ui.end_row();
                        ui.label("Username:");
                        ui.add(egui::TextEdit::singleline(&mut self.add_password_username));
                        ui.end_row();
                        ui.label("Password:");
                        ui.horizontal(|ui| {
                            let eye_icon = if self.add_password_show_password { "🙈" } else { "👁" };
                            if ui.button(eye_icon).on_hover_text(if self.add_password_show_password { "Hide Password" } else { "Reveal Password" }).clicked() {
                                self.add_password_show_password = !self.add_password_show_password;
                            }
                            ui.add(egui::TextEdit::singleline(&mut self.add_password_password).password(!self.add_password_show_password));
                        });
                        ui.end_row();
                    });

                    ui.add_space(15.0);
                    ui.group(|ui| {
                        ui.label("Password Generator:");
                        ui.add_space(5.0);
                        ui.horizontal(|ui| {
                            ui.label("Length:");
                            ui.add(egui::Slider::new(&mut self.add_password_gen_length, 4..=64));
                        });
                        ui.horizontal(|ui| {
                            ui.checkbox(&mut self.add_password_gen_numbers, "Numbers");
                            ui.checkbox(&mut self.add_password_gen_symbols, "Symbols");
                            ui.checkbox(&mut self.add_password_gen_mixed_case, "Mixed Case");
                        });
                        ui.add_space(5.0);
                        if ui.button("🎲 Generate Password").clicked() {
                            let mut pool = b"abcdefghijklmnopqrstuvwxyz".to_vec();
                            if self.add_password_gen_mixed_case { pool.extend_from_slice(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"); }
                            if self.add_password_gen_numbers { pool.extend_from_slice(b"0123456789"); }
                            if self.add_password_gen_symbols { pool.extend_from_slice(b"!@#$%^&*()_+-=[]{}|;':\",./<>?"); }
                            let mut rng = thread_rng();
                            let mut new_pass = String::with_capacity(self.add_password_gen_length);
                            for _ in 0..self.add_password_gen_length {
                                new_pass.push(pool[rng.gen_range(0..pool.len())] as char);
                            }
                            self.add_password_password = new_pass;
                        }
                    });

                    ui.add_space(15.0);
                    ui.horizontal(|ui| {
                        if ui.button("OK").clicked() {
                            let new_cred = PasswordEntry {
                                name: None,
                                url: Some(self.add_password_url.clone()),
                                username: Some(self.add_password_username.clone()),
                                password: Some(self.add_password_password.clone()),
                                date: Some(current_date_string()),
                            };
                            self.decrypted_entries.push(VaultItem::Credential(new_cred));
                            self.execute_repack(ctx.clone(), None);
                            self.logs.push("✅ Manually added a new password.".to_string());
                            self.show_add_password_modal = false;
                            self.add_password_url.clear();
                            self.add_password_username.clear();
                            self.add_password_password.zeroize();
                            self.add_password_password.clear();
                            self.add_password_show_password = false;
                        }
                        if ui.button("Cancel").clicked() {
                            self.show_add_password_modal = false;
                            self.add_password_url.clear();
                            self.add_password_username.clear();
                            self.add_password_password.zeroize();
                            self.add_password_password.clear();
                            self.add_password_show_password = false;
                        }
                    });
                });
        }

        if self.show_z_mount_modal {
            egui::Window::new("▶ Mount Virtual Drive (Z:\\)")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.label("Select operation mode for the Z:\\ drive:");
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        if ui.button("📥 Import (Auto-Ingest CSVs)").clicked() {
                            self.show_z_mount_modal = false;
                            self.import_mode.store(true, std::sync::atomic::Ordering::SeqCst);
                            self.is_mounting = true;
                            self.mount_progress = 0.0;
                            let (tx, rx) = std::sync::mpsc::channel();
                            self.mount_rx = Some(rx);
                            let log_tx = self.log_tx.clone();
                            let ctx_clone = ctx.clone();
                            let drop_zone = self.active_drop_zone.clone();
                            std::thread::spawn(move || {
                                // Actively scrub any leftover files to guarantee a pristine Import space
                                if let Some(dz) = drop_zone {
                                    if let Ok(entries) = std::fs::read_dir(&dz) {
                                        for entry in entries.flatten() {
                                            if entry.path().is_file() {
                                                let _ = std::fs::remove_file(entry.path());
                                            }
                                        }
                                    }
                                }
                                let success = mount_z_drive(&mut |msg| { let _ = log_tx.send(msg); });
                                let _ = tx.send(success);
                                ctx_clone.request_repaint();
                            });
                        }
                        if ui.button("📤 Export (Safe Extraction)").clicked() {
                            self.show_z_mount_modal = false;
                            self.import_mode.store(false, std::sync::atomic::Ordering::SeqCst);
                            self.is_mounting = true;
                            self.mount_progress = 0.0;
                            let (tx, rx) = std::sync::mpsc::channel();
                            self.mount_rx = Some(rx);
                            let log_tx = self.log_tx.clone();
                            let ctx_clone = ctx.clone();
                            let entries = self.decrypted_entries.clone();
                            let drop_zone = self.active_drop_zone.clone();

                            std::thread::spawn(move || {
                                let mut log = |msg: String| { let _ = log_tx.send(msg); };
                                let success = mount_z_drive(&mut log);

                                if success {
                                    if let Some(dz) = drop_zone {
                                        let passwords: Vec<_> = entries.into_iter().filter_map(|e| {
                                            if let VaultItem::Credential(c) = e { Some(c) } else { None }
                                        }).collect();

                                        if !passwords.is_empty() {
                                            #[derive(Serialize)]
                                            struct StandardCsvEntry<'a> {
                                                name: &'a str,
                                                url: &'a str,
                                                username: &'a str,
                                                password: &'a str,
                                            }

                                            match csv::Writer::from_path(dz.join("passwords_export.csv")) {
                                                Ok(mut wtr) => {
                                                    let mut export_success = true;
                                                    for p in &passwords {
                                                        let name = p.name.as_deref().unwrap_or("").trim();
                                                        let url = p.url.as_deref().unwrap_or("").trim();
                                                        let username = p.username.as_deref().unwrap_or("").trim();
                                                        let password = p.password.as_deref().unwrap_or("").trim();

                                                        if url.is_empty() && password.is_empty() { continue; }

                                                        let export_row = StandardCsvEntry { name, url, username, password };
                                                        if let Err(e) = wtr.serialize(&export_row) {
                                                            log(format!("  -> ⚠ Failed to write password row: {}", e));
                                                            export_success = false;
                                                        }
                                                    }
                                                    let _ = wtr.flush();
                                                    if export_success {
                                                        log(format!("✅ Securely extracted {} passwords to Z:\\passwords_export.csv", passwords.len()));
                                                    }
                                                }
                                                Err(e) => log(format!("  -> ❌ Failed to create CSV: {}", e)),
                                            }
                                        }
                                    }
                                }

                                let _ = tx.send(success);
                                ctx_clone.request_repaint();
                            });
                        }
                        if ui.button("❌ Cancel").clicked() {
                            self.show_z_mount_modal = false;
                        }
                    });
                });
        }

        if self.is_importing_file {
            egui::Window::new("File Import")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.label(format!("Importing: {}", self.import_file_name));
                    ui.add_space(10.0);

                    if !self.import_finished {
                        ui.label(&self.import_status);
                        let progress_text = format!("{:.0}%", self.import_progress * 100.0);
                        ui.add(egui::ProgressBar::new(self.import_progress).animate(true).text(progress_text));
                    } else {
                        ui.label(&self.import_status);
                        ui.add_space(10.0);
                        ui.vertical_centered(|ui| {
                            if ui.button("OK").clicked() { self.is_importing_file = false; }
                        });
                    }
                });
        }

        if !self.is_unlocked {
            // Render the login screen natively in the CentralPanel so it scales safely
            egui::CentralPanel::default()
                .frame(egui::Frame::central_panel(&ctx.style()).inner_margin(40.0))
                .show(ctx, |panel_ui| {
                    // By wrapping the login UI in a ScrollArea, we break egui's layout caching.
                    // This forces it to re-evaluate the required size on every frame, fixing the
                    // bug where the window wouldn't resize correctly on the second login.
                    egui::ScrollArea::vertical().show(panel_ui, |ui| {
                        ui.heading("PassWardN");
                        ui.add_space(10.0);
                let mut active_vault = None;

                // Scan the grid to find the first surviving vault
                if let Some(forced_vault) = &self.dropped_vault_path {
                    active_vault = Some(forced_vault.clone());
                } else {
                    let mut size_counts = std::collections::HashMap::new();
                    for path in &self.vault_paths {
                        let len = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
                        if len >= 140 {
                            *size_counts.entry(len).or_insert(0) += 1;
                        }
                    }
                    let mut consensus_size = 0;
                    let mut max_count = 0;
                    for (&size, &count) in &size_counts {
                        if count > max_count || (count == max_count && size > consensus_size) {
                            max_count = count;
                            consensus_size = size;
                        }
                    }
                    for path in &self.vault_paths {
                        let len = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
                        if len == consensus_size && consensus_size >= 140 {
                            active_vault = Some(path.clone());
                            break;
                        }
                    }
                }
                let is_new_vault = active_vault.is_none();

                if let Some(forced_vault) = self.dropped_vault_path.clone() {
                    ui.label(egui::RichText::new("Force Load Vault").heading());
                    ui.horizontal(|ui| {
                        ui.label(format!("📦 Staged: {}", forced_vault.file_name().unwrap_or_default().to_string_lossy()));
                        if ui.button("❌ Cancel").clicked() {
                            self.dropped_vault_path = None;
                        }
                    });
                    ui.add_space(10.0);
                    ui.label("Enter Password OR drop a Dongle to unlock Vault:");
                } else if is_new_vault {
                    ui.label(egui::RichText::new("Welcome to PassWardN!").heading());
                    ui.label("Let's set up your new secure vault.");
                    ui.add_space(10.0);

                    ui.label("Vault Locations (Redundancy Grid):");
                    let mut to_remove = None;
                    let table_height = (self.vault_paths.len() as f32 * 30.0).max(30.0);
                    ui.allocate_ui(egui::vec2(ui.available_width(), table_height), |ui| {
                        egui_extras::TableBuilder::new(ui)
                            .striped(true)
                            .resizable(false)
                            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                            .column(egui_extras::Column::remainder().clip(true))
                            .column(egui_extras::Column::exact(30.0))
                            .min_scrolled_height(0.0)
                            .body(|mut body| {
                                for (i, path) in self.vault_paths.iter().enumerate() {
                                    body.row(30.0, |mut row| {
                                        row.col(|ui| {
                                            let p_str = path.to_string_lossy().to_string();
                                            ui.label(&p_str).on_hover_text(&p_str);
                                        });
                                        row.col(|ui| {
                                            if self.vault_paths.len() > 1 && ui.button("❌").clicked() {
                                                to_remove = Some(i);
                                            }
                                        });
                                    });
                                }
                            });
                    });
                    if let Some(i) = to_remove {
                        self.vault_paths.remove(i);
                        save_custom_paths(&self.vault_paths);
                    }
                    if ui.button("➕ Add Flash Drive / Location...").clicked() {
                        if let Some(mut dir) = open_directory_dialog() {
                            dir.push("secure_vault.bin");
                            if !self.vault_paths.contains(&dir) {
                                self.vault_paths.push(dir);
                                save_custom_paths(&self.vault_paths);
                            }
                        }
                    }

                    ui.add_space(15.0);
                    ui.label("Set Master Password (Required):");
                } else {
                    ui.label("Enter Password OR drop a Dongle to unlock Vault:");
                }
                ui.add_space(5.0);
                ui.horizontal(|ui| {
                    let response = ui.add(egui::TextEdit::singleline(&mut self.password_input).password(true));
                    let btn_text = if is_new_vault { "Initialize Vaults" } else { "Unlock" };
                    if ui.button(btn_text).clicked() || (response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))) {
                        let mut salt = [0u8; 16];
                        let mut slot1 = [0u8; 60];
                        let mut slot2 = [0u8; 60];
                        let mut slot3 = [0u8; 60];
                        let is_new_vault_flag: bool;

                        // Vault Header Architecture: [4-byte "GVL2"] [16-byte Salt] [60-byte Slot 1] [60-byte Slot 2] [60-byte Slot 3]
                        if let Some(path) = &active_vault {
                            is_new_vault_flag = false;
                            if let Ok(mut file) = std::fs::File::open(path) {
                                let mut magic = [0u8; 4];
                                let _ = file.read_exact(&mut magic);
                                if &magic == b"GVLT" || &magic == b"GVL2" {
                                    let _ = file.read_exact(&mut salt);
                                    let _ = file.read_exact(&mut slot1);
                                    let _ = file.read_exact(&mut slot2);
                                    if &magic == b"GVL2" { let _ = file.read_exact(&mut slot3); }
                                    self.logs.push(format!("Vault found at {:?}. Reading multi-slot header...", path));
                                } else {
                                    self.logs.push("❌ Invalid vault header! Please Clean Test Ground.".to_string());
                                    return;
                                }
                            } else {
                                self.logs.push("❌ Failed to open existing vault file.".to_string());
                                return;
                            }
                        } else {
                            is_new_vault_flag = true;
                            thread_rng().fill_bytes(&mut salt);
                        }

                        let password_present = !self.password_input.is_empty();
                        let mut dongle_present = false;
                        let mut dongle_hash = [0u8; 32];
                        if let Some(path) = &self.dropped_file_path {
                            self.logs.push("  -> Generating BLAKE3 hardware hash from Dongle...".to_string());
                            match std::fs::File::open(path) {
                                Ok(mut f) => {
                                    let mut hasher = blake3::Hasher::new();
                                    let _ = std::io::copy(&mut f, &mut hasher);
                                    dongle_hash = hasher.finalize().into();
                                    dongle_present = true;
                                },
                                Err(e) => { self.logs.push(format!("❌ Failed to open Dongle: {}", e)); return; }
                            }
                        }

                        if !password_present && !dongle_present {
                            self.logs.push("⚠ Please provide a Master Password OR a Digital Dongle to unlock.".to_string());
                            return;
                        }

                        let mut unlocked_master_key = None;

                        if is_new_vault_flag {
                            if !password_present {
                                self.logs.push("⚠ A Master Password is strictly REQUIRED to initialize a new vault. You can add a dongle alongside it.".to_string());
                                return;
                            }
                            self.show_setup_recovery_modal = true;
                            return;
                        } else {
                            if dongle_present {
                                let kek_dongle = derive_kek(&dongle_hash, &salt);
                                if let Some(mk) = decrypt_slot(&kek_dongle, &slot2) {
                                    unlocked_master_key = Some(mk);
                                    self.logs.push("✅ Unlocked via Digital Dongle!".to_string());
                                } else {
                                    self.logs.push("❌ Dongle rejected (or not set up).".to_string());
                                }
                            }

                            if unlocked_master_key.is_none() && password_present {
                                let kek_pass = derive_kek(self.password_input.as_bytes(), &salt);
                                if let Some(mk) = decrypt_slot(&kek_pass, &slot1) {
                                    unlocked_master_key = Some(mk);
                                    self.logs.push("✅ Unlocked via Master Password!".to_string());
                                } else {
                                    self.logs.push("❌ Incorrect Master Password.".to_string());
                                }
                            }
                        }

                        let master_key = match unlocked_master_key {
                            Some(k) => k,
                            None => {
                                self.failed_login_attempts += 1;
                                self.logs.push(format!("❌ Access Denied: Invalid Credentials. (Failed attempts: {})", self.failed_login_attempts));
                                if self.failed_login_attempts >= 5 {
                                    self.show_recovery_modal = true;
                                    self.logs.push("🚨 Too many failed attempts. Emergency Recovery unlocked.".to_string());
                                }
                                self.password_input.zeroize();
                                return;
                            }
                        };

                        self.failed_login_attempts = 0;
                        self.show_recovery_modal = false;

                        let target_path = active_vault.clone().unwrap_or_else(|| self.vault_paths[0].clone());
                        self.is_decrypting = true;
                        self.logs.push("⏳ Decrypting vault payloads in background...".to_string());

                        let (unlock_tx, unlock_rx) = std::sync::mpsc::channel();
                        self.unlock_rx = Some(unlock_rx);
                        let ctx_clone = ctx.clone();
                        let mk_clone = master_key;
                        let target_path_clone = target_path.clone();
                        let d_hash = if dongle_present { Some(dongle_hash) } else { None };

                        std::thread::spawn(move || {
                            match decrypt_vault(&target_path_clone, &mk_clone) {
                                Ok(entries) => {
                                    let _ = unlock_tx.send(Ok(UnlockSuccess {
                                        entries,
                                        master_key: mk_clone,
                                        dongle_hash: d_hash,
                                    }));
                                }
                                Err(e) => {
                                    let _ = unlock_tx.send(Err(e.to_string()));
                                }
                            }
                            ctx_clone.request_repaint();
                        });

                        // Securely wipe the plaintext password from memory
                        self.password_input.zeroize();
                    }
                });

                ui.add_space(10.0);
                ui.label("Optional Digital Dongle\n(Drag & Drop a file here):");
                if let Some(path) = self.dropped_file_path.clone() {
                    ui.horizontal(|ui| {
                        ui.label(format!("🔑 Staged: {}", path.file_name().unwrap_or_default().to_string_lossy()));
                        if ui.button("❌ Remove").clicked() {
                            self.dropped_file_path = None;
                            self.logs.push("Dongle removed. Falling back to Password mode.".to_string());
                        }
                    });
                } else {
                    ui.label("No dongle staged. (Password mode)");
                }

                if self.show_setup_recovery_modal {
                    egui::Window::new("🔐 Setup Recovery Questions")
                        .collapsible(false)
                        .resizable(false)
                        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                        .show(ctx, |ui| {
                            ui.label("Would you like to set up recovery questions?");
                            ui.label("If you forget your master password, these answers can restore your vault.");
                            ui.add_space(10.0);
                            ui.label("In what city were you born?");
                            ui.add(egui::TextEdit::singleline(&mut self.setup_a1).hint_text("optional").desired_width(200.0));
                            ui.add_space(5.0);
                            ui.label("Name of your first pet?");
                            ui.add(egui::TextEdit::singleline(&mut self.setup_a2).hint_text("optional").desired_width(200.0));
                            ui.add_space(5.0);
                            ui.label("Model of your first car?");
                            ui.add(egui::TextEdit::singleline(&mut self.setup_a3).hint_text("optional").desired_width(200.0));
                            ui.add_space(15.0);
                            ui.horizontal(|ui| {
                                let btn_text = if self.setup_a1.is_empty() && self.setup_a2.is_empty() && self.setup_a3.is_empty() {
                                    "Skip & Create Vault"
                                } else {
                                    "OK (Create Vault)"
                                };
                                if ui.button(btn_text).clicked() {
                                    self.show_setup_recovery_modal = false;
                                    self.logs.push("  -> Initializing new Redundancy Grid with Key Slots...".to_string());

                                    let mut salt = [0u8; 16];
                                    thread_rng().fill_bytes(&mut salt);

                                    let mut mk = [0u8; 32];
                                    thread_rng().fill_bytes(&mut mk);

                                    let kek_pass = derive_kek(self.password_input.as_bytes(), &salt);
                                    let slot1 = encrypt_slot(&kek_pass, &mk);

                                    let mut slot2 = [0u8; 60];
                                    let mut dongle_hash_opt = None;
                                    if let Some(path) = &self.dropped_file_path {
                                        if let Ok(mut f) = std::fs::File::open(path) {
                                            let mut hasher = blake3::Hasher::new();
                                            let _ = std::io::copy(&mut f, &mut hasher);
                                            let dh: [u8; 32] = hasher.finalize().into();
                                            dongle_hash_opt = Some(dh);
                                            let kek_dongle = derive_kek(&dh, &salt);
                                            slot2 = encrypt_slot(&kek_dongle, &mk);
                                        }
                                    }

                                    let mut slot3 = [0u8; 60];
                                    if self.setup_a1.is_empty() && self.setup_a2.is_empty() && self.setup_a3.is_empty() {
                                        thread_rng().fill_bytes(&mut slot3); // User opted out, fill with unrecoverable noise
                                    } else {
                                        let kek_recovery = derive_recovery_kek(&self.setup_a1, &self.setup_a2, &self.setup_a3, &salt);
                                        slot3 = encrypt_slot(&kek_recovery, &mk);
                                    }

                                    for path in &self.vault_paths {
                                        if let Some(parent) = path.parent() {
                                            let _ = std::fs::create_dir_all(parent);
                                        }
                                        if let Ok(mut file) = OpenOptions::new().write(true).create(true).truncate(true).open(path) {
                                            let _ = file.write_all(b"GVL2");
                                            let _ = file.write_all(&salt);
                                            let _ = file.write_all(&slot1);
                                            let _ = file.write_all(&slot2);
                                            let _ = file.write_all(&slot3);
                                        }
                                    }

                                    let target_path = self.vault_paths[0].clone();
                                    self.is_decrypting = true;
                                    self.logs.push("⏳ Decrypting vault payloads in background...".to_string());

                                    let (unlock_tx, unlock_rx) = std::sync::mpsc::channel();
                                    self.unlock_rx = Some(unlock_rx);
                                    let ctx_clone = ctx.clone();
                                    let mk_clone = mk;

                                    std::thread::spawn(move || {
                                        match decrypt_vault(&target_path, &mk_clone) {
                                            Ok(entries) => {
                                                let _ = unlock_tx.send(Ok(UnlockSuccess {
                                                    entries,
                                                    master_key: mk_clone,
                                                    dongle_hash: dongle_hash_opt,
                                                }));
                                            }
                                            Err(e) => {
                                                let _ = unlock_tx.send(Err(e.to_string()));
                                            }
                                        }
                                        ctx_clone.request_repaint();
                                    });

                                    self.password_input.zeroize();
                                    self.setup_a1.clear();
                                    self.setup_a2.clear();
                                    self.setup_a3.clear();
                                }
                                if ui.button("Cancel").clicked() {
                                    self.show_setup_recovery_modal = false;
                                }
                            });
                        });
                }

                if self.show_recovery_modal {
                    egui::Window::new("🚨 Emergency Recovery")
                        .collapsible(false)
                        .resizable(false)
                        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                        .show(ctx, |ui| {
                            ui.label("You have entered the wrong password 5 times.");
                            ui.label("Please answer your security questions to recover your vault.");
                            ui.add_space(10.0);
                            ui.label("In what city were you born?");
                            ui.add(egui::TextEdit::singleline(&mut self.recovery_a1).desired_width(200.0));
                            ui.add_space(5.0);
                            ui.label("Name of your first pet?");
                            ui.add(egui::TextEdit::singleline(&mut self.recovery_a2).desired_width(200.0));
                            ui.add_space(5.0);
                            ui.label("Model of your first car?");
                            ui.add(egui::TextEdit::singleline(&mut self.recovery_a3).desired_width(200.0));
                            ui.add_space(15.0);
                            ui.horizontal(|ui| {
                                if ui.button("Unlock Vault").clicked() {
                                    let mut valid = false;
                                    let mut recovered_mk = [0u8; 32];

                                    if let Some(path) = &active_vault {
                                        if let Ok(mut file) = std::fs::File::open(path) {
                                            let mut magic = [0u8; 4];
                                            if file.read_exact(&mut magic).is_ok() && &magic == b"GVL2" {
                                                let mut salt = [0u8; 16];
                                                let mut slot1 = [0u8; 60];
                                                let mut slot2 = [0u8; 60];
                                                let mut slot3 = [0u8; 60];
                                                let _ = file.read_exact(&mut salt);
                                                let _ = file.read_exact(&mut slot1);
                                                let _ = file.read_exact(&mut slot2);
                                                let _ = file.read_exact(&mut slot3);

                                                let kek_recovery = derive_recovery_kek(&self.recovery_a1, &self.recovery_a2, &self.recovery_a3, &salt);
                                                if let Some(mk) = decrypt_slot(&kek_recovery, &slot3) {
                                                    valid = true;
                                                    recovered_mk = mk;
                                                }
                                            } else {
                                                self.logs.push("❌ This vault is using an old format and doesn't support Recovery Questions.".to_string());
                                            }
                                        }
                                    }

                                    if valid {
                                        self.logs.push("✅ Vault recovered successfully via Security Questions!".to_string());
                                        self.logs.push("⚠ NOTE: Please go to Settings and change your Master Password immediately.".to_string());
                                        self.show_recovery_modal = false;
                                        self.failed_login_attempts = 0;
                                        self.password_input.zeroize();
                                        self.recovery_a1.clear();
                                        self.recovery_a2.clear();
                                        self.recovery_a3.clear();

                                        let target_path = active_vault.clone().unwrap_or_else(|| self.vault_paths[0].clone());
                                        self.is_decrypting = true;
                                        let (unlock_tx, unlock_rx) = std::sync::mpsc::channel();
                                        self.unlock_rx = Some(unlock_rx);
                                        let ctx_clone = ctx.clone();

                                        std::thread::spawn(move || {
                                            match decrypt_vault(&target_path, &recovered_mk) {
                                                Ok(entries) => {
                                                    let _ = unlock_tx.send(Ok(UnlockSuccess {
                                                        entries,
                                                        master_key: recovered_mk,
                                                        dongle_hash: None,
                                                    }));
                                                }
                                                Err(e) => { let _ = unlock_tx.send(Err(e.to_string())); }
                                            }
                                            ctx_clone.request_repaint();
                                        });
                                    } else {
                                        self.logs.push("❌ Incorrect recovery answers.".to_string());
                                    }
                                }
                                if ui.button("Cancel").clicked() {
                                    self.show_recovery_modal = false;
                                }
                            });
                        });
                }

                if !is_new_vault {
                    ui.add_space(30.0);
                    ui.separator();
                    ui.add_space(10.0);
                    ui.heading("Password Generator");
                    ui.add_space(5.0);
                    if !self.login_generated_password.is_empty() {
                        ui.add(egui::TextEdit::singleline(&mut self.login_generated_password)
                            .font(egui::TextStyle::Monospace)
                            .desired_width(ui.available_width()));
                        if ui.button("📋 Copy to Clipboard").clicked() {
                            ui.output_mut(|o| o.copied_text = self.login_generated_password.clone());
                            self.logs.push("📋 Generated password copied to clipboard.".to_string());
                        }
                        ui.add_space(10.0);
                    }
                    ui.horizontal(|ui| {
                        ui.label("Length:");
                        ui.add(egui::Slider::new(&mut self.add_password_gen_length, 4..=64));
                    });
                    ui.horizontal(|ui| {
                        ui.checkbox(&mut self.add_password_gen_numbers, "Numbers");
                        ui.checkbox(&mut self.add_password_gen_symbols, "Symbols");
                        ui.checkbox(&mut self.add_password_gen_mixed_case, "Mixed Case");
                    });
                    ui.add_space(5.0);
                    if ui.button("🎲 Generate Password").clicked() {
                        let mut pool = b"abcdefghijklmnopqrstuvwxyz".to_vec();
                        if self.add_password_gen_mixed_case { pool.extend_from_slice(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"); }
                        if self.add_password_gen_numbers { pool.extend_from_slice(b"0123456789"); }
                        if self.add_password_gen_symbols { pool.extend_from_slice(b"!@#$%^&*()_+-=[]{}|;':\",./<>?"); }
                        let mut rng = thread_rng();
                        let mut new_pass = String::with_capacity(self.add_password_gen_length);
                        for _ in 0..self.add_password_gen_length {
                            new_pass.push(pool[rng.gen_range(0..pool.len())] as char);
                        }
                        self.login_generated_password = new_pass;
                    }
                }
                    });
                });
        } else {
            // Render the fully scalable main app interface
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.heading("PassWardN");
                ui.add_space(10.0);

                if self.show_change_credentials_modal {
                    egui::Window::new("⚙ Change Settings")
                        .collapsible(false)
                        .resizable(false)
                        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                        .show(ctx, |ui| {
                            ui.label("Select what you would like to change:");
                            ui.horizontal_wrapped(|ui| {
                                ui.radio_value(&mut self.credential_change_mode, CredentialChangeMode::ChangePassword, "Change Password");
                                ui.radio_value(&mut self.credential_change_mode, CredentialChangeMode::ChangeDongle, "Dongle");
                                ui.radio_value(&mut self.credential_change_mode, CredentialChangeMode::ManageLocations, "Vault Locations");
                                ui.radio_value(&mut self.credential_change_mode, CredentialChangeMode::ChangeRecovery, "Recovery Questions");
                            });
                            ui.add_space(5.0);

                            ui.label("Current Master Password (Required):");
                            ui.add(egui::TextEdit::singleline(&mut self.old_password_input).password(true).font(egui::TextStyle::Monospace));
                            ui.add_space(10.0);

                            if self.credential_change_mode == CredentialChangeMode::ChangePassword {
                                ui.label("New Master Password:");
                                ui.add(egui::TextEdit::singleline(&mut self.new_password_input).password(true).font(egui::TextStyle::Monospace));
                            } else if self.credential_change_mode == CredentialChangeMode::ChangeDongle {
                                if self.remove_dongle_staged {
                                    ui.horizontal(|ui| {
                                        ui.label("🗑 Dongle removal staged. Apply changes to execute.");
                                        if ui.button("❌ Cancel").clicked() {
                                            self.remove_dongle_staged = false;
                                        }
                                    });
                                } else if let Some(path) = self.new_dropped_file_path.clone() {
                                    ui.horizontal(|ui| {
                                        ui.label(format!("🔑 New Dongle: {}", path.file_name().unwrap_or_default().to_string_lossy()));
                                        if ui.button("❌ Remove").clicked() {
                                            self.new_dropped_file_path = None;
                                        }
                                    });
                                } else {
                                    ui.horizontal(|ui| {
                                        ui.label("Drop a file to add/change your dongle.");
                                        if ui.button("🗑 Remove Current Dongle").clicked() {
                                            self.remove_dongle_staged = true;
                                        }
                                    });
                                }
                            } else if self.credential_change_mode == CredentialChangeMode::ManageLocations {
                                ui.label("Staged Vault Locations:");
                                let mut to_remove = None;
                                let table_height = (self.staged_vault_paths.len() as f32 * 30.0).max(30.0);
                                ui.allocate_ui(egui::vec2(ui.available_width(), table_height), |ui| {
                                    egui_extras::TableBuilder::new(ui)
                                        .striped(true)
                                        .resizable(false)
                                        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                                        .column(egui_extras::Column::remainder().clip(true))
                                        .column(egui_extras::Column::exact(30.0))
                                        .min_scrolled_height(0.0)
                                        .body(|mut body| {
                                            for (i, path) in self.staged_vault_paths.iter().enumerate() {
                                                body.row(30.0, |mut row| {
                                                    row.col(|ui| {
                                                        let p_str = path.to_string_lossy().to_string();
                                                        ui.label(&p_str).on_hover_text(&p_str);
                                                    });
                                                    row.col(|ui| {
                                                        if self.staged_vault_paths.len() > 1 && ui.button("❌").clicked() {
                                                            to_remove = Some(i);
                                                        }
                                                    });
                                                });
                                            }
                                        });
                                });
                                if let Some(i) = to_remove {
                                    self.staged_vault_paths.remove(i);
                                }
                                if ui.button("➕ Add Flash Drive / Location...").clicked() {
                                    if let Some(mut dir) = open_directory_dialog() {
                                        dir.push("secure_vault.bin");
                                        if !self.staged_vault_paths.contains(&dir) {
                                            self.staged_vault_paths.push(dir);
                                        }
                                    }
                                }
                            } else if self.credential_change_mode == CredentialChangeMode::ChangeRecovery {
                                ui.label("In what city were you born?");
                                ui.add(egui::TextEdit::singleline(&mut self.change_recovery_a1).hint_text("optional").desired_width(200.0));
                                ui.add_space(5.0);
                                ui.label("Name of your first pet?");
                                ui.add(egui::TextEdit::singleline(&mut self.change_recovery_a2).hint_text("optional").desired_width(200.0));
                                ui.add_space(5.0);
                                ui.label("Model of your first car?");
                                ui.add(egui::TextEdit::singleline(&mut self.change_recovery_a3).hint_text("optional").desired_width(200.0));
                            }

                            ui.add_space(15.0);
                            ui.horizontal(|ui| {
                                if ui.button("Apply Changes").clicked() {
                                    if self.old_password_input.is_empty() {
                                        self.logs.push("⚠ Current Master Password is required.".to_string());
                                        return;
                                    }

                                    if self.credential_change_mode == CredentialChangeMode::ChangePassword && self.new_password_input.is_empty() {
                                        self.logs.push("⚠ New Master Password cannot be empty.".to_string());
                                        return;
                                    }

                                    // Verify Old Password
                                    let mut valid_old = false;
                                    let mut active_path = None;

                                    for path in &self.vault_paths {
                                        if path.exists() && std::fs::metadata(path).map(|m| m.len()).unwrap_or(0) >= 140 {
                                            active_path = Some(path.clone());
                                            break;
                                        }
                                    }

                                    let mut salt = [0u8; 16];
                                    let mut slot1 = [0u8; 60];
                                    let mut slot2 = [0u8; 60];
                                let mut slot3 = [0u8; 60];

                                    if let Some(p) = active_path {
                                        if let Ok(mut file) = std::fs::File::open(&p) {
                                            let mut magic = [0u8; 4];
                                            let _ = file.read_exact(&mut magic);
                                        if &magic == b"GVLT" || &magic == b"GVL2" {
                                                let _ = file.read_exact(&mut salt);
                                                let _ = file.read_exact(&mut slot1);
                                                let _ = file.read_exact(&mut slot2);
                                            if &magic == b"GVL2" { let _ = file.read_exact(&mut slot3); }

                                                let kek_pass = derive_kek(self.old_password_input.as_bytes(), &salt);
                                                if let Some(mk) = decrypt_slot(&kek_pass, &slot1) {
                                                    if mk == *self.shared_key.lock().unwrap() {
                                                        valid_old = true;
                                                    }
                                                }
                                            }
                                        }
                                    }

                                    if !valid_old {
                                        self.logs.push("❌ Current Master Password is incorrect!".to_string());
                                        return;
                                    }

                                    let current_master_key = *self.shared_key.lock().unwrap();

                                    if self.credential_change_mode == CredentialChangeMode::ChangePassword {
                                        let kek_pass = derive_kek(self.new_password_input.as_bytes(), &salt);
                                        slot1 = encrypt_slot(&kek_pass, &current_master_key);
                                    } else if self.credential_change_mode == CredentialChangeMode::ChangeDongle {
                                        if self.remove_dongle_staged {
                                            slot2 = [0u8; 60];
                                            self.active_dongle_hash = None;
                                        } else if let Some(path) = &self.new_dropped_file_path {
                                            if let Ok(mut f) = std::fs::File::open(path) {
                                                let mut hasher = blake3::Hasher::new();
                                                let _ = std::io::copy(&mut f, &mut hasher);
                                                let h: [u8; 32] = hasher.finalize().into();
                                                let kek_dongle = derive_kek(&h, &salt);
                                                slot2 = encrypt_slot(&kek_dongle, &current_master_key);
                                                self.active_dongle_hash = Some(h);
                                            }
                                        } else {
                                            self.logs.push("⚠ Please drop a file or stage a removal.".to_string());
                                            return;
                                        }
                                    } else if self.credential_change_mode == CredentialChangeMode::ManageLocations {
                                        self.vault_paths = self.staged_vault_paths.clone();
                                        save_custom_paths(&self.vault_paths);
                                    } else if self.credential_change_mode == CredentialChangeMode::ChangeRecovery {
                                        if self.change_recovery_a1.is_empty() && self.change_recovery_a2.is_empty() && self.change_recovery_a3.is_empty() {
                                            thread_rng().fill_bytes(&mut slot3);
                                        } else {
                                            let kek_recovery = derive_recovery_kek(&self.change_recovery_a1, &self.change_recovery_a2, &self.change_recovery_a3, &salt);
                                            slot3 = encrypt_slot(&kek_recovery, &current_master_key);
                                        }
                                    }

                                let mut header = vec![0u8; 200];
                                header[0..4].copy_from_slice(b"GVL2");
                                    header[4..20].copy_from_slice(&salt);
                                    header[20..80].copy_from_slice(&slot1);
                                    header[80..140].copy_from_slice(&slot2);
                                header[140..200].copy_from_slice(&slot3);

                                    self.execute_repack(ctx.clone(), Some(header));

                                    self.show_change_credentials_modal = false;
                                    self.old_password_input.zeroize();
                                    self.old_password_input.clear();
                                    self.new_password_input.zeroize();
                                    self.new_password_input.clear();
                                    self.new_dropped_file_path = None;
                                    self.remove_dongle_staged = false;
                                    self.change_recovery_a1.clear();
                                    self.change_recovery_a2.clear();
                                    self.change_recovery_a3.clear();
                                }
                                if ui.button("Cancel").clicked() {
                                    self.show_change_credentials_modal = false;
                                    self.old_password_input.zeroize();
                                    self.old_password_input.clear();
                                    self.new_password_input.zeroize();
                                    self.new_password_input.clear();
                                    self.new_dropped_file_path = None;
                                    self.remove_dongle_staged = false;
                                    self.change_recovery_a1.clear();
                                    self.change_recovery_a2.clear();
                                    self.change_recovery_a3.clear();
                                }
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    if ui.button("Delete All").clicked() {
                                        self.show_delete_all_modal = true;
                                    }
                                });
                            });
                        });
                }

                if self.show_delete_all_modal {
                    egui::Window::new("⚠ Confirm Delete All")
                        .collapsible(false)
                        .resizable(false)
                        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                        .show(ctx, |ui| {
                            ui.label("Are you sure you want to permanently delete all vaults and settings?");
                            ui.label("Enter Master Password to confirm:");
                            ui.add(egui::TextEdit::singleline(&mut self.delete_all_password_input).password(true));
                            ui.add_space(10.0);
                            ui.horizontal(|ui| {
                                if ui.button("OK").clicked() {
                                    let mut valid = false;
                                    let mut active_path = None;
                                    for path in &self.vault_paths {
                                        if path.exists() && std::fs::metadata(path).map(|m| m.len()).unwrap_or(0) >= 140 {
                                            active_path = Some(path.clone());
                                            break;
                                        }
                                    }
                                    if let Some(p) = active_path {
                                        if let Ok(mut file) = std::fs::File::open(&p) {
                                            let mut magic = [0u8; 4];
                                            let _ = file.read_exact(&mut magic);
                                        if &magic == b"GVLT" || &magic == b"GVL2" {
                                                let mut salt = [0u8; 16];
                                                let mut slot1 = [0u8; 60];
                                                let mut slot2 = [0u8; 60];
                                                let _ = file.read_exact(&mut salt);
                                                let _ = file.read_exact(&mut slot1);
                                                let _ = file.read_exact(&mut slot2);

                                                let kek_pass = derive_kek(self.delete_all_password_input.as_bytes(), &salt);
                                                if let Some(mk) = decrypt_slot(&kek_pass, &slot1) {
                                                    if mk == *self.shared_key.lock().unwrap() {
                                                        valid = true;
                                                    }
                                                }
                                            }
                                        }
                                    }

                                    if valid {
                                        let decoy_path = Path::new(r"C:\Users\Administrator\AppData\Local\Microsoft\Windows\WebCache\ghost_decoy.bin");
                                        let mut cleaned = false;
                                        for path in &self.vault_paths {
                                            if path.exists() {
                                                let _ = std::fs::remove_file(path);
                                                cleaned = true;
                                            }
                                        }
                                        if decoy_path.exists() {
                                            let _ = std::fs::remove_file(decoy_path);
                                            cleaned = true;
                                        }
                                        let cfg_bin = config_path();
                                        if cfg_bin.exists() { let _ = std::fs::remove_file(&cfg_bin); cleaned = true; }
                                        let cfg_json = cfg_bin.with_extension("json");
                                        if cfg_json.exists() { let _ = std::fs::remove_file(&cfg_json); cleaned = true; }

                                        if cleaned {
                                            self.logs.push("🗑 All vaults and configurations have been permanently deleted.".to_string());
                                        } else {
                                            self.logs.push("🗑 Test ground is already clean.".to_string());
                                        }
                                        self.vault_paths = get_vault_paths();

                                        self.is_unlocked = false;
                                        self.revealed_passwords.clear();
                                        if let Some(pos) = ctx.input(|i| i.viewport().outer_rect).map(|r| r.min) {
                                            ctx.send_viewport_cmd(egui::ViewportCommand::OuterPosition(egui::pos2(pos.x + 325.0, pos.y + 50.0)));
                                        }
                                        ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(550.0, 500.0)));
                                        self.decrypted_entries.clear();
                                        self.ghost_driver_running = false;
                                        self.z_drive_mounted = false;
                                        self.old_password_input.zeroize();
                                        self.old_password_input.clear();
                                        self.new_password_input.zeroize();
                                        self.new_password_input.clear();
                                        self.delete_all_password_input.zeroize();
                                        self.delete_all_password_input.clear();
                                        self.active_dongle_hash = None;
                                        self.dropped_vault_path = None;
                                        self.dropped_file_path = None;
                                        self.remove_dongle_staged = false;
                                        self.is_repacking = false;
                                        self.item_to_delete = None;
                                        self.is_importing_file = false;
                                        self.import_rx = None;
                                        self.show_sync_results_modal = false;
                                        self.show_dump_modal = false;
                                        self.show_z_mount_modal = false;
                                        self.show_grid_heal_modal = false;
                                        self.show_change_credentials_modal = false;
                                        self.show_delete_all_modal = false;
                                        self.login_generated_password.zeroize();
                                        self.login_generated_password.clear();
                                    self.show_add_password_modal = false;
                                    self.add_password_url.clear();
                                    self.add_password_username.clear();
                                    self.add_password_password.zeroize();
                                    self.add_password_password.clear();
                                    self.add_password_show_password = false;
                                        let mut local_logs = Vec::new();
                                        teardown_drop_zone(&mut |msg| local_logs.push(msg));
                                        self.logs.extend(local_logs);
                                        self.active_drop_zone = None;
                                    } else {
                                        self.logs.push("❌ Incorrect Master Password. Deletion aborted.".to_string());
                                        self.show_delete_all_modal = false;
                                        self.delete_all_password_input.zeroize();
                                        self.delete_all_password_input.clear();
                                    }
                                }
                                if ui.button("Cancel").clicked() {
                                    self.show_delete_all_modal = false;
                                    self.delete_all_password_input.zeroize();
                                    self.delete_all_password_input.clear();
                                }
                            });
                        });
                }

                let mut idx_to_clear = None;
                if let Some(idx) = self.item_to_delete {
                    egui::Window::new("⚠ Confirm Deletion")
                        .collapsible(false)
                        .resizable(false)
                        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                        .show(ctx, |ui| {
                            ui.label("Are you sure you want to permanently delete this item?");
                            ui.label("This action will immediately repack the vault and cannot be undone.");
                            ui.add_space(10.0);
                            ui.horizontal(|ui| {
                                if ui.button("🗑 Delete Permanently").clicked() {
                                    if idx < self.decrypted_entries.len() {
                                        self.decrypted_entries.remove(idx);
                                        self.execute_repack(ctx.clone(), None);
                                    }
                                    idx_to_clear = Some(true);
                                }
                                if ui.button("Cancel").clicked() {
                                    idx_to_clear = Some(true);
                                }
                            });
                        });
                }
                if idx_to_clear.is_some() { self.item_to_delete = None; }

                egui_extras::StripBuilder::new(ui)
                    .size(egui_extras::Size::exact(50.0)) // Controls area
                    .size(egui_extras::Size::exact(40.0)) // Saved Passwords Heading
                        .size(egui_extras::Size::relative(0.55)) // Passwords Table
                    .size(egui_extras::Size::exact(40.0)) // Stored Files Heading
                        .size(egui_extras::Size::remainder()) // Files Area
                    .vertical(|mut strip| {
                        strip.cell(|ui| {
                            ui.horizontal(|ui| {
                                if self.z_drive_mounted {
                                    if ui.add_enabled(!self.is_unmounting && !self.is_mounting, egui::Button::new("⏏ Unmount Z:")).clicked() {
                                        self.is_unmounting = true;
                                        self.mount_progress = 0.0;
                                        let (tx, rx) = std::sync::mpsc::channel();
                                        self.unmount_rx = Some(rx);
                                        let log_tx = self.log_tx.clone();
                                        let ctx_clone = ctx.clone();
                                        std::thread::spawn(move || {
                                            unmount_z_drive(&mut |msg| { let _ = log_tx.send(msg); });
                                            let _ = tx.send(());
                                            ctx_clone.request_repaint();
                                        });
                                    }
                                } else {
                                    if ui.add_enabled(!self.is_unmounting && !self.is_mounting, egui::Button::new("▶ Mount Z:")).clicked() {
                                        self.show_z_mount_modal = true;
                                    }
                                }

                                if self.active_drop_zone.is_some() {
                                let is_import = self.import_mode.load(std::sync::atomic::Ordering::SeqCst);
                                let mode_str = if is_import { "Mode: Import" } else { "Mode: Export" };
                                let icon = if is_import { "👁" } else { "🔒" };
                                    if self.z_drive_mounted {
                                    ui.label(format!("{} Intercepting at: Z:\\ ({})", icon, mode_str));
                                    } else {
                                    ui.label(format!("{} Intercepting ({})", icon, mode_str));
                                    }
                                }
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    if ui.add_enabled(!self.is_mounting && !self.is_unmounting, egui::Button::new("🔒 Lock Vault")).clicked() {
                                        self.is_unlocked = false;
                                        self.revealed_passwords.clear();
                                        if let Some(pos) = ctx.input(|i| i.viewport().outer_rect).map(|r| r.min) {
                                                ctx.send_viewport_cmd(egui::ViewportCommand::OuterPosition(egui::pos2(pos.x + 325.0, pos.y + 50.0)));
                                        }
                                    ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(550.0, 500.0)));
                                        self.decrypted_entries.clear();
                                        self.ghost_driver_running = false;
                                        self.z_drive_mounted = false;
                                        self.old_password_input.zeroize();
                                        self.old_password_input.clear();
                                        self.new_password_input.zeroize();
                                        self.new_password_input.clear();
                                        self.active_dongle_hash = None;
                                        self.dropped_vault_path = None;
                                        self.dropped_file_path = None;
                                    self.remove_dongle_staged = false;
                                        self.is_repacking = false;
                                        self.item_to_delete = None;
                                        self.is_importing_file = false;
                                        self.import_rx = None;
                                        self.show_sync_results_modal = false;
                                        self.show_dump_modal = false;
                                    self.show_z_mount_modal = false;
                                        self.show_grid_heal_modal = false;
                                        self.show_delete_all_modal = false;
                                        self.delete_all_password_input.zeroize();
                                        self.delete_all_password_input.clear();
                                        self.login_generated_password.zeroize();
                                        self.login_generated_password.clear();
                                        self.recovery_a1.clear();
                                        self.recovery_a2.clear();
                                        self.recovery_a3.clear();
                                        self.change_recovery_a1.clear();
                                        self.change_recovery_a2.clear();
                                        self.change_recovery_a3.clear();
                                        self.show_add_password_modal = false;
                                        self.add_password_url.clear();
                                        self.add_password_username.clear();
                                        self.add_password_password.zeroize();
                                        self.add_password_password.clear();
                                        self.add_password_show_password = false;
                                        let mut local_logs = Vec::new();
                                        teardown_drop_zone(&mut |msg| local_logs.push(msg));
                                        self.logs.extend(local_logs);
                                        self.active_drop_zone = None;
                                        self.logs.push("🔒 Vault locked and memory cleared.".to_string());
                                    }
                                    if ui.add_enabled(!self.is_mounting && !self.is_unmounting && !self.is_repacking && !self.is_importing_file, egui::Button::new("⚙ Change Credentials")).clicked() {
                                        self.show_change_credentials_modal = true;
                                        self.staged_vault_paths = self.vault_paths.clone();
                                    }
                                    if ui.add_enabled(!self.is_mounting && !self.is_unmounting && !self.is_repacking && !self.is_importing_file, egui::Button::new("💥 Dump")).clicked() {
                                        self.show_dump_modal = true;
                                    }
                                });
                            });
                        });

                        strip.cell(|ui| {
                            ui.horizontal(|ui| {
                                ui.heading("Saved Passwords");
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    if ui.button("📂 Browse for CSV...").clicked() {
                                        if let Some(path) = open_file_dialog() {
                                            self.import_csv(path, ctx.clone());
                                        }
                                    }
                                    if ui.button("➕ Add Password").clicked() {
                                        self.show_add_password_modal = true;
                                    }
                                    ui.label("⬇ Drag & Drop CSV files");
                                });
                            });
                        });

                        strip.cell(|ui| {
                            let credentials: Vec<_> = self.decrypted_entries.iter().enumerate().filter_map(|(idx, e)| {
                                if let VaultItem::Credential(c) = e { Some((idx, c)) } else { None }
                            }).collect();

                            if credentials.is_empty() {
                                ui.label("No passwords stored yet. Drop a CSV to gobble!");
                            } else {
                                // Calculate exactly 1/3 of the available window width.
                                // We pad 80px to accommodate the 60px delete button + 20px for the scrollbar.
                                let table_width = ui.available_width();
                                // We now have 4 data columns, so we adjust the width calculation.
                                let col_w = ((table_width - 80.0) / 4.0).max(100.0);

                                // Bind the UI ID to the window width to forcefully bypass egui's column caching mechanism.
                                ui.push_id(table_width as u32, |ui| {
                                    egui_extras::TableBuilder::new(ui)
                                        .striped(true)
                                        .resizable(true)
                                        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                                        .column(egui_extras::Column::initial(col_w).at_least(100.0).clip(true))
                                        .column(egui_extras::Column::initial(col_w).at_least(100.0).clip(true))
                                        .column(egui_extras::Column::initial(col_w).at_least(100.0).clip(true))
                                        .column(egui_extras::Column::remainder().at_least(160.0).clip(true).resizable(false))
                                        .column(egui_extras::Column::exact(60.0).clip(true).resizable(false))
                                        .min_scrolled_height(0.0)
                                        .header(35.0, |mut header| {
                                        header.col(|ui| { ui.label(egui::RichText::new("🌐 URL").strong().color(egui::Color32::LIGHT_BLUE)); });
                                        header.col(|ui| { ui.label(egui::RichText::new("👤 Username").strong().color(egui::Color32::LIGHT_BLUE)); });
                                        header.col(|ui| { ui.label(egui::RichText::new("🔑 Password").strong().color(egui::Color32::LIGHT_BLUE)); });
                                        header.col(|ui| { ui.label(egui::RichText::new("📅 Date").strong().color(egui::Color32::LIGHT_BLUE)); });
                                        header.col(|ui| { ui.label(egui::RichText::new("🗑").strong().color(egui::Color32::LIGHT_RED)); });
                                    })
                                    .body(|mut body| {
                                        for (idx, entry) in credentials {
                                            body.row(35.0, |mut row| {
                                                row.col(|ui| {
                                                    let raw_url = entry.url.as_deref().unwrap_or("Unknown Site");
                                                    let clean_url = raw_url.strip_prefix("https://").unwrap_or_else(|| raw_url.strip_prefix("http://").unwrap_or(raw_url));
                                                    let mut url_str = clean_url.to_string();
                                                    let resp = ui.add(egui::TextEdit::singleline(&mut url_str).frame(false).font(egui::TextStyle::Monospace));
                                                    if resp.clicked() {
                                                        ui.output_mut(|o| o.copied_text = raw_url.to_string());
                                                        self.logs.push(format!("📋 Copied URL for {} to clipboard.", clean_url));
                                                    }
                                                    resp.on_hover_text("Click to copy URL");
                                                });
                                                row.col(|ui| {
                                                    let user = entry.username.as_deref().unwrap_or("No Username");
                                                    let mut user_str = user.to_string();
                                                    let resp = ui.add(egui::TextEdit::singleline(&mut user_str).frame(false).font(egui::TextStyle::Monospace));
                                                    if resp.clicked() {
                                                        ui.output_mut(|o| o.copied_text = user.to_string());
                                                        self.logs.push("📋 Copied Username to clipboard.".to_string());
                                                    }
                                                    resp.on_hover_text("Click to copy Username");
                                                });
                                                row.col(|ui| {
                                                    let pass = entry.password.as_deref().unwrap_or("No Password");
                                                    let is_revealed = self.revealed_passwords.contains(&idx);

                                                    ui.horizontal(|ui| {
                                                        let eye_icon = if is_revealed { "🙈" } else { "👁" };
                                                        if ui.button(eye_icon).on_hover_text(if is_revealed { "Hide Password" } else { "Reveal Password" }).clicked() {
                                                            if is_revealed { self.revealed_passwords.remove(&idx); }
                                                            else { self.revealed_passwords.insert(idx); }
                                                        }
                                                        let display_pass = if is_revealed { pass } else { "********" };
                                                        let mut pass_str = display_pass.to_string();
                                                        let resp = ui.add(egui::TextEdit::singleline(&mut pass_str).frame(false).font(egui::TextStyle::Monospace));
                                                        if resp.clicked() {
                                                            ui.output_mut(|o| o.copied_text = pass.to_string());
                                                            self.logs.push("📋 Copied Password to clipboard.".to_string());
                                                        }
                                                        resp.on_hover_text("Click to copy Password");
                                                    });
                                                });
                                                row.col(|ui| {
                                                    let mut date_str = entry.date.as_deref().unwrap_or("N/A").to_string();
                                                    let resp = ui.add(egui::TextEdit::singleline(&mut date_str).frame(false).font(egui::TextStyle::Monospace));
                                                    if resp.clicked() {
                                                        ui.output_mut(|o| o.copied_text = date_str.clone());
                                                        self.logs.push("📋 Copied Date to clipboard.".to_string());
                                                    }
                                                    resp.on_hover_text("Click to copy Date");
                                                });
                                                row.col(|ui| {
                                                    if ui.add_enabled(!self.is_repacking, egui::Button::new("🗑")).on_hover_text("Delete Password").clicked() {
                                                        self.item_to_delete = Some(idx);
                                                    }
                                                });
                                            });
                                        }
                                    });
                                });
                            }
                        });

                        strip.cell(|ui| {
                            ui.horizontal(|ui| {
                                ui.heading("Stored Files");
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    ui.label("⬇ Drag & Drop arbitrary files to secure them");
                                });
                            });
                        });

                        strip.cell(|ui| {
                            let secure_files: Vec<_> = self.decrypted_entries.iter().enumerate().filter_map(|(idx, e)| {
                                match e {
                                    VaultItem::SecureFile { filename, file_size, data } => Some((idx, filename.clone(), *file_size, Some(data.clone()), 0, "N/A".to_string())),
                                    VaultItem::FileIndex { filename, file_size, chunk_offset } => Some((idx, filename.clone(), *file_size, None, *chunk_offset, "N/A".to_string())),
                                    VaultItem::SecureFileV2 { filename, file_size, added_date, data } => Some((idx, filename.clone(), *file_size, Some(data.clone()), 0, added_date.clone())),
                                    VaultItem::FileIndexV2 { filename, file_size, added_date, chunk_offset } => Some((idx, filename.clone(), *file_size, None, *chunk_offset, added_date.clone())),
                                    _ => None
                                }
                            }).collect();

                            if secure_files.is_empty() {
                                ui.label("No files stored yet. Drop a file to secure it!");
                            } else {
                                let table_width = ui.available_width();
                                let col_w = ((table_width - 90.0) / 3.0).max(100.0);

                                // Add a +1 to the UI ID so it doesn't conflict with the password table cache above!
                                ui.push_id(table_width as u32 + 1, |ui| {
                                    egui_extras::TableBuilder::new(ui)
                                        .striped(true)
                                        .resizable(true)
                                        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                                        .column(egui_extras::Column::initial(col_w).at_least(100.0).clip(true))
                                        .column(egui_extras::Column::initial(col_w).at_least(100.0).clip(true))
                                        .column(egui_extras::Column::remainder().at_least(100.0).clip(true).resizable(false))
                                        .column(egui_extras::Column::exact(90.0).clip(true).resizable(false))
                                        .min_scrolled_height(0.0)
                                        .header(35.0, |mut header| {
                                            header.col(|ui| { ui.label(egui::RichText::new("📄 File Name").strong().color(egui::Color32::LIGHT_BLUE)); });
                                            header.col(|ui| { ui.label(egui::RichText::new("⚖ Size").strong().color(egui::Color32::LIGHT_BLUE)); });
                                            header.col(|ui| { ui.label(egui::RichText::new("📅 Date").strong().color(egui::Color32::LIGHT_BLUE)); });
                                            header.col(|ui| { ui.label(egui::RichText::new("⚙").strong().color(egui::Color32::LIGHT_GRAY)); });
                                        })
                                        .body(|mut body| {
                                            for (idx, filename, file_size, data_opt, chunk_offset, added_date) in secure_files {
                                                body.row(35.0, |mut row| {
                                                    row.col(|ui| {
                                                        let mut f_name = filename.clone();
                                                        let resp = ui.add(egui::TextEdit::singleline(&mut f_name).frame(false).font(egui::TextStyle::Monospace));
                                                        if resp.clicked() {
                                                            ui.output_mut(|o| o.copied_text = filename.clone());
                                                            self.logs.push(format!("📋 Copied File Name: {}", filename));
                                                        }
                                                        resp.on_hover_text("Click to copy File Name");
                                                    });
                                                    row.col(|ui| {
                                                        let mut size_str = if file_size >= 1024 * 1024 * 1024 {
                                                            format!("{:.2} GB", file_size as f64 / (1024.0 * 1024.0 * 1024.0))
                                                        } else if file_size >= 1024 * 1024 {
                                                            format!("{:.2} MB", file_size as f64 / (1024.0 * 1024.0))
                                                        } else if file_size >= 1024 {
                                                            format!("{:.2} KB", file_size as f64 / 1024.0)
                                                        } else {
                                                            format!("{} B", file_size)
                                                        };
                                                        let resp = ui.add(egui::TextEdit::singleline(&mut size_str).frame(false).font(egui::TextStyle::Monospace));
                                                        if resp.clicked() {
                                                            ui.output_mut(|o| o.copied_text = size_str.clone());
                                                            self.logs.push("📋 Copied File Size.".to_string());
                                                        }
                                                        resp.on_hover_text("Click to copy File Size");
                                                    });
                                                    row.col(|ui| {
                                                        let mut date_str = added_date.clone();
                                                        let resp = ui.add(egui::TextEdit::singleline(&mut date_str).frame(false).font(egui::TextStyle::Monospace));
                                                        if resp.clicked() {
                                                            ui.output_mut(|o| o.copied_text = added_date.clone());
                                                            self.logs.push("📋 Copied Date.".to_string());
                                                        }
                                                        resp.on_hover_text("Click to copy Date");
                                                    });
                                                    row.col(|ui| {
                                                        ui.horizontal(|ui| {
                                                            if ui.button("⬇").on_hover_text("Extract File").clicked() {
                                                                if let Some(out_path) = save_file_dialog(&filename) {
                                                                    self.logs.push(format!("💥 Extracting {}...", filename));
                                                                    let filename_clone = filename.clone();
                                                                    let log_tx = self.log_tx.clone();
                                                                    let ctx_clone = ctx.clone();
                                                                    let mk_clone = *self.shared_key.lock().unwrap();
                                                                    std::thread::spawn(move || {
                                                                        let log = |msg: String| {
                                                                            let _ = log_tx.send(msg);
                                                                            ctx_clone.request_repaint();
                                                                        };
                                                                        if let Some(data) = data_opt {
                                                                            if let Err(e) = std::fs::write(&out_path, data) {
                                                                                log(format!("  -> ⚠ Failed to extract {}: {}", filename_clone, e));
                                                                            } else {
                                                                                log(format!("✅ Successfully extracted legacy RAM file {} to {:?}", filename_clone, out_path));
                                                                            }
                                                                        } else {
                                                                            let target_vault = get_vault_paths().into_iter().find(|p| p.exists()).unwrap();
                                                                            if let Ok(mut file) = std::fs::File::open(target_vault) {
                                                                                if file.seek(SeekFrom::Start(chunk_offset)).is_ok() {
                                                                                    let mut len_buf = [0u8; 4];
                                                                                    if file.read_exact(&mut len_buf).is_ok() {
                                                                                        let chunk_len = u32::from_le_bytes(len_buf) as usize;
                                                                                        let mut nonce_buf = [0u8; 12];
                                                                                        if file.read_exact(&mut nonce_buf).is_ok() {
                                                                                            let mut ct_buf = vec![0u8; chunk_len];
                                                                                            if file.read_exact(&mut ct_buf).is_ok() {
                                                                                                let key = Key::from_slice(&mk_clone);
                                                                                                let cipher = ChaCha20Poly1305::new(key);
                                                                                                let nonce = Nonce::from_slice(&nonce_buf);
                                                                                                if let Ok(pt) = cipher.decrypt(nonce, ct_buf.as_ref()) {
                                                                                                    if let Err(e) = std::fs::write(&out_path, pt) {
                                                                                                        log(format!("  -> ⚠ Failed to extract {}: {}", filename_clone, e));
                                                                                                    } else {
                                                                                                        log(format!("✅ Successfully extracted disk chunk {} to {:?}", filename_clone, out_path));
                                                                                                    }
                                                                                                    return;
                                                                                                }
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                            log(format!("❌ Failed to read or decrypt disk chunk for {}", filename_clone));
                                                                        }
                                                                    });
                                                                } else {
                                                                    self.logs.push(format!("Extraction of {} cancelled.", filename));
                                                                }
                                                            }
                                                            if ui.add_enabled(!self.is_repacking, egui::Button::new("🗑")).on_hover_text("Delete File").clicked() {
                                                                self.item_to_delete = Some(idx);
                                                            }
                                                        });
                                                    });
                                                });
                                            }
                                        });
                                });
                            }
                        });
                    });
            });
        }
    }
}

fn main() -> Result<(), eframe::Error> {
    // Example implementation
    let decoy_path = Path::new(r"C:\Users\Administrator\AppData\Local\Microsoft\Windows\WebCache\ghost_decoy.bin");

    // Create a 10GB fake vault (takes 0 bytes on disk initially)
    if let Err(e) = create_sparse_decoy(decoy_path, 10 * 1024 * 1024 * 1024) {
        eprintln!("Failed to create decoy: {}", e);
    }

    let (log_tx, log_rx) = channel();
    let (entries_tx, entries_rx) = channel();

    // Load the icon for the app window and taskbar
    let icon_data = {
        let icon_bytes = include_bytes!("icon.ico");
        let image = image::load_from_memory_with_format(icon_bytes, image::ImageFormat::Ico)
            .expect("Failed to load icon")
            .into_rgba8();
        let (width, height) = image.dimensions();
        std::sync::Arc::new(egui::IconData {
            rgba: image.into_raw(),
            width,
            height,
        })
    };

    // Start the eframe UI
    let options = eframe::NativeOptions {
        centered: true,
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([550.0, 650.0])
            .with_icon(icon_data),
        ..Default::default()
    };

    eframe::run_native(
        "PassWardN",
        options,
        Box::new(move |cc| {
            let mut fonts = egui::FontDefinitions::default();

            fonts.font_data.insert("bold_font".to_owned(), egui::FontData::from_static(include_bytes!("my_font_Bold.ttf")));
            fonts.font_data.insert("regular_font".to_owned(), egui::FontData::from_static(include_bytes!("my_font_Regular.ttf")));
            fonts.font_data.insert("bold_emoji".to_owned(), egui::FontData::from_static(include_bytes!("my_emoji_Bold.ttf")));
            fonts.font_data.insert("regular_emoji".to_owned(), egui::FontData::from_static(include_bytes!("my_emoji_Regular.ttf")));

            if let Some(prop) = fonts.families.get_mut(&egui::FontFamily::Proportional) {
                prop.insert(0, "bold_font".to_owned());
                prop.insert(1, "bold_emoji".to_owned());
            }

            if let Some(mono) = fonts.families.get_mut(&egui::FontFamily::Monospace) {
                mono.insert(0, "regular_font".to_owned());
                mono.insert(1, "regular_emoji".to_owned());
            }

            cc.egui_ctx.set_fonts(fonts);

            let mut style = egui::Style {
                visuals: egui::Visuals::dark(),
                ..Default::default()
            };

            style.visuals.extreme_bg_color = egui::Color32::from_gray(25);
            style.visuals.panel_fill = egui::Color32::from_gray(32);
            style.visuals.window_fill = egui::Color32::from_gray(32);
            style.visuals.widgets.inactive.bg_fill = egui::Color32::TRANSPARENT;
            style.visuals.widgets.inactive.bg_stroke = egui::Stroke::new(1.0, egui::Color32::from_rgba_unmultiplied(255, 255, 255, 20));
            style.visuals.widgets.hovered.bg_fill = egui::Color32::TRANSPARENT;
            style.visuals.widgets.hovered.bg_stroke = egui::Stroke::new(2.0, egui::Color32::from_rgb(50, 150, 255));
            style.visuals.widgets.active.bg_fill = egui::Color32::from_rgba_unmultiplied(50, 150, 255, 30);
            style.visuals.widgets.active.bg_stroke = egui::Stroke::new(2.0, egui::Color32::from_rgb(100, 200, 255));
            style.visuals.widgets.noninteractive.fg_stroke.color = egui::Color32::WHITE;
            style.visuals.widgets.inactive.fg_stroke.color = egui::Color32::WHITE;
            style.visuals.widgets.hovered.fg_stroke.color = egui::Color32::WHITE;
            style.visuals.widgets.active.fg_stroke.color = egui::Color32::WHITE;

            style.text_styles = [
                (egui::TextStyle::Heading, egui::FontId::new(22.0, egui::FontFamily::Proportional)),
                (egui::TextStyle::Body, egui::FontId::new(18.0, egui::FontFamily::Proportional)),
                (egui::TextStyle::Monospace, egui::FontId::new(18.0, egui::FontFamily::Monospace)),
                (egui::TextStyle::Button, egui::FontId::new(18.0, egui::FontFamily::Proportional)),
                (egui::TextStyle::Small, egui::FontId::new(14.0, egui::FontFamily::Proportional)),
            ].into();

            cc.egui_ctx.set_style(style);
            Box::new(PasswordVaultApp::new(log_tx, log_rx, entries_tx, entries_rx))
        }),
    )
}
