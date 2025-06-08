use std::path::PathBuf;
use async_trait::async_trait;
use crate::domain::entities::{EncryptedFile, EncryptionMetadata};

// ============================================================================
// ENCRYPTION PORTS
// ============================================================================

/// Port for password-based key derivation
/// Abstracts the actual key derivation algorithm (Argon2, PBKDF2, etc.)
pub trait KeyDerivation {
    /// Derive encryption key from password and salt
    fn derive_key(
        &self,
        password: &str,
        salt: &[u8],
        iterations: Option<u32>,
    ) -> crate::Result<Vec<u8>>;

    /// Generate cryptographically secure salt
    fn generate_salt(&self) -> crate::Result<Vec<u8>>;

    /// Validate password strength
    fn validate_password_strength(&self, password: &str) -> crate::Result<PasswordStrength>;
}

/// Port for symmetric encryption operations
#[async_trait]
pub trait SymmetricEncryption {
    /// Encrypt data with given key and return ciphertext + metadata
    async fn encrypt(
        &self,
        plaintext: &[u8],
        key: &[u8],
    ) -> crate::Result<EncryptionResult>;

    /// Decrypt data with given key and metadata
    async fn decrypt(
        &self,
        ciphertext: &[u8],
        key: &[u8],
        metadata: &EncryptionMetadata,
    ) -> crate::Result<Vec<u8>>;

    /// Get the algorithm identifier
    fn algorithm_name(&self) -> &'static str;

    /// Get required key size for this algorithm
    fn key_size(&self) -> usize;

    /// Get nonce/IV size for this algorithm  
    fn nonce_size(&self) -> usize;
}

/// Port for secure file operations
#[async_trait]
pub trait SecureFileOperations {
    /// Encrypt a file in-place or to a new location
    async fn encrypt_file(
        &self,
        source_path: &PathBuf,
        password: &str,
        destination_path: Option<&PathBuf>,
    ) -> crate::Result<EncryptedFile>;

    /// Decrypt a file to a temporary or specified location
    async fn decrypt_file(
        &self,
        encrypted_file: &EncryptedFile,
        password: &str,
        destination_path: Option<&PathBuf>,
    ) -> crate::Result<PathBuf>;

    /// Verify file integrity without full decryption
    async fn verify_file_integrity(
        &self,
        encrypted_file: &EncryptedFile,
        password: &str,
    ) -> crate::Result<bool>;

    /// Get file encryption metadata without decrypting
    async fn read_metadata(&self, file_path: &PathBuf) -> crate::Result<EncryptionMetadata>;
}

// ============================================================================
// SECURE STORAGE PORTS  
// ============================================================================

/// Port for secure storage operations
#[async_trait]
pub trait SecureStorage {
    /// Store encrypted file with metadata
    async fn store_encrypted_file(
        &self,
        encrypted_file: &EncryptedFile,
        metadata: &EncryptionMetadata,
    ) -> crate::Result<StorageHandle>;

    /// Retrieve encrypted file by handle
    async fn retrieve_encrypted_file(
        &self,
        handle: &StorageHandle,
    ) -> crate::Result<EncryptedFile>;

    /// List all stored encrypted files
    async fn list_encrypted_files(&self) -> crate::Result<Vec<StorageEntry>>;

    /// Delete encrypted file permanently
    async fn delete_encrypted_file(&self, handle: &StorageHandle) -> crate::Result<()>;

    /// Get storage statistics (used space, file count, etc.)
    async fn get_storage_stats(&self) -> crate::Result<StorageStats>;
}

// ============================================================================
// SUPPORTING TYPES
// ============================================================================

/// Result of encryption operation
#[derive(Debug)]
pub struct EncryptionResult {
    pub ciphertext: Vec<u8>,
    pub metadata: EncryptionMetadata,
    pub verification_tag: Option<Vec<u8>>, // For authenticated encryption
}

/// Password strength assessment
#[derive(Debug, Clone, PartialEq)]
pub enum PasswordStrength {
    Weak { issues: Vec<String> },
    Medium { suggestions: Vec<String> },
    Strong,
    VeryStrong,
}

/// Handle to stored encrypted file
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StorageHandle {
    pub id: String,
    pub storage_path: PathBuf,
}

/// Entry in encrypted file storage
#[derive(Debug, Clone)]
pub struct StorageEntry {
    pub handle: StorageHandle,
    pub original_name: String,
    pub encrypted_size: u64,
    pub created_at: chrono::DateTime<chrono::Local>,
    pub last_accessed: Option<chrono::DateTime<chrono::Local>>,
    pub metadata: EncryptionMetadata,
}

/// Storage system statistics
#[derive(Debug, Clone)]
pub struct StorageStats {
    pub total_files: usize,
    pub total_size_bytes: u64,
    pub available_space_bytes: u64,
    pub oldest_file: Option<chrono::DateTime<chrono::Local>>,
    pub newest_file: Option<chrono::DateTime<chrono::Local>>,
}

impl PasswordStrength {
    pub fn is_acceptable(&self) -> bool {
        matches!(self, PasswordStrength::Medium { .. } | PasswordStrength::Strong | PasswordStrength::VeryStrong)
    }

    pub fn score(&self) -> u8 {
        match self {
            PasswordStrength::Weak { .. } => 1,
            PasswordStrength::Medium { .. } => 2,
            PasswordStrength::Strong => 3,
            PasswordStrength::VeryStrong => 4,
        }
    }
}

impl StorageHandle {
    pub fn new(id: String, storage_path: PathBuf) -> Self {
        Self { id, storage_path }
    }

    pub fn from_path(storage_path: PathBuf) -> Self {
        let id = storage_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();
        Self { id, storage_path }
    }
}