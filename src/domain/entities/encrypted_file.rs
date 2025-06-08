use std::path::PathBuf;
use chrono::{DateTime, Local};

// Domain entity representing an encrypted capture file
// Encapsulates business rules around file encryption/decryption
#[derive(Debug, Clone)]
pub struct EncryptedFile {
    pub path: PathBuf,
    pub original_name: String,
    pub size_bytes: u64,
    pub created_at: DateTime<Local>,
    pub is_valid: bool,
}

// Value object for encryption metadata
// Contains cryptographic parameters (but not the actual key!)
#[derive(Debug, Clone)]
pub struct EncryptionMetadata {
    pub salt: [u8; crate::SALT_SIZE],
    pub nonce: [u8; crate::NONCE_SIZE], 
    pub algorithm: EncryptionAlgorithm,
}

// Enum for supported encryption algorithms
// Using enum makes it type-safe and extensible
#[derive(Debug, Clone, PartialEq)]
pub enum EncryptionAlgorithm {
    Aes256Gcm,
    // Future algorithms can be added here
}

impl EncryptedFile {
    // Constructor with business validation
    pub fn new(
        path: PathBuf,
        original_name: String,
        size_bytes: u64,
    ) -> crate::Result<Self> {
        // Business rule: file must have .enc extension
        if !path.extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext == "enc")
            .unwrap_or(false) 
        {
            return Err("Encrypted file must have .enc extension".into());
        }

        // Business rule: original name cannot be empty
        if original_name.trim().is_empty() {
            return Err("Original filename cannot be empty".into());
        }

        Ok(Self {
            path,
            original_name,
            size_bytes,
            created_at: Local::now(),
            is_valid: true, // Will be validated by encryption service
        })
    }

    // Business method: get decrypted filename
    pub fn decrypted_filename(&self) -> String {
        // Remove .enc extension and restore original
        self.original_name.clone()
    }

    // Business method: check if file size is reasonable
    pub fn is_reasonable_size(&self) -> bool {
        // Business rule: files should be between 100 bytes and 10GB
        const MIN_SIZE: u64 = 100;
        const MAX_SIZE: u64 = 10 * 1024 * 1024 * 1024; // 10GB
        
        self.size_bytes >= MIN_SIZE && self.size_bytes <= MAX_SIZE
    }

    // Business method: estimate decryption time based on size
    pub fn estimated_decryption_seconds(&self) -> u64 {
        // Rough estimate: 100MB/second decryption speed
        const BYTES_PER_SECOND: u64 = 100 * 1024 * 1024;
        (self.size_bytes / BYTES_PER_SECOND).max(1)
    }
}

impl EncryptionMetadata {
    pub fn new(salt: [u8; crate::SALT_SIZE], nonce: [u8; crate::NONCE_SIZE]) -> Self {
        Self {
            salt,
            nonce,
            algorithm: EncryptionAlgorithm::Aes256Gcm,
        }
    }

    // Business method: get header size for this algorithm
    pub fn header_size(&self) -> usize {
        match self.algorithm {
            EncryptionAlgorithm::Aes256Gcm => crate::HEADER_SIZE,
        }
    }
}