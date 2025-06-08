use std::path::PathBuf;
use async_trait::async_trait;
use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit, aead::Aead};
use argon2::{Argon2, password_hash::{PasswordHasher, SaltString}};
use rand::Rng;
use memmap2::Mmap;
use std::fs;

use crate::domain::ports::encryption::*;
use crate::domain::entities::{EncryptedFile, EncryptionMetadata};

// ============================================================================
// ARGON2 KEY DERIVATION IMPLEMENTATION
// ============================================================================

/// Concrete implementation of KeyDerivation using Argon2
pub struct Argon2KeyDerivation {
    argon2: Argon2<'static>,
    default_iterations: u32,
}

impl KeyDerivation for Argon2KeyDerivation {
    fn derive_key(
        &self,
        password: &str,
        salt: &[u8],
        iterations: Option<u32>,
    ) -> crate::Result<Vec<u8>> {
        // Convert salt to SaltString for Argon2
        let salt_string = SaltString::encode_b64(salt)
            .map_err(|e| format!("Salt encoding error: {}", e))?;
        
        // Use custom iterations if provided
        let argon2 = if let Some(iter) = iterations {
            Argon2::new(
                argon2::Algorithm::Argon2id,
                argon2::Version::V0x13,
                argon2::Params::new(
                    65536, // memory cost (64 MB)
                    iter,  // time cost
                    1,     // parallelism
                    Some(32), // output length
                ).map_err(|e| format!("Argon2 params error: {}", e))?,
            )
        } else {
            self.argon2.clone()
        };
        
        // Hash the password
        let password_hash = argon2.hash_password(password.as_bytes(), &salt_string)
            .map_err(|e| format!("Key derivation failed: {}", e))?;
        
        // Extract the hash bytes
        let hash = password_hash.hash
            .ok_or("No hash in password hash")?;
        let hash_bytes = hash.as_bytes();
        
        Ok(hash_bytes[..32].to_vec()) // Return first 32 bytes for AES-256
    }
    
    fn generate_salt(&self) -> crate::Result<Vec<u8>> {
        let salt: [u8; crate::SALT_SIZE] = rand::thread_rng().gen();
        Ok(salt.to_vec())
    }
    
    fn validate_password_strength(&self, password: &str) -> crate::Result<PasswordStrength> {
        let mut issues = Vec::new();
        let mut suggestions = Vec::new();
        
        // Length check
        if password.len() < 8 {
            issues.push("Password too short (minimum 8 characters)".to_string());
        } else if password.len() < 12 {
            suggestions.push("Consider using at least 12 characters".to_string());
        }
        
        // Character diversity checks
        let has_lowercase = password.chars().any(|c| c.is_lowercase());
        let has_uppercase = password.chars().any(|c| c.is_uppercase());
        let has_digit = password.chars().any(|c| c.is_ascii_digit());
        let has_special = password.chars().any(|c| !c.is_alphanumeric());
        
        let char_types = [has_lowercase, has_uppercase, has_digit, has_special]
            .iter()
            .filter(|&&x| x)
            .count();
        
        match char_types {
            0..=1 => issues.push("Password must contain different character types".to_string()),
            2 => suggestions.push("Add more character variety (uppercase, lowercase, digits, symbols)".to_string()),
            _ => {} // Good diversity
        }
        
        // Common password checks
        if Self::is_common_password(password) {
            issues.push("Password is too common".to_string());
        }
        
        // Pattern checks
        if Self::has_keyboard_pattern(password) {
            suggestions.push("Avoid keyboard patterns".to_string());
        }
        
        // Determine strength
        let strength = if !issues.is_empty() {
            PasswordStrength::Weak { issues }
        } else if !suggestions.is_empty() {
            PasswordStrength::Medium { suggestions }
        } else if password.len() >= 16 && char_types >= 3 {
            PasswordStrength::VeryStrong
        } else {
            PasswordStrength::Strong
        };
        
        Ok(strength)
    }
}

impl Argon2KeyDerivation {
    pub fn new() -> Self {
        Self {
            argon2: Argon2::default(),
            default_iterations: 3, // Reasonable default for interactive use
        }
    }
    
    pub fn with_iterations(mut self, iterations: u32) -> Self {
        self.default_iterations = iterations;
        self
    }
    
    fn is_common_password(password: &str) -> bool {
        // Check against common passwords
        const COMMON_PASSWORDS: &[&str] = &[
            "password", "123456", "123456789", "qwerty", "abc123", 
            "password123", "admin", "letmein", "welcome", "monkey"
        ];
        
        let lower_password = password.to_lowercase();
        COMMON_PASSWORDS.iter().any(|&common| lower_password.contains(common))
    }
    
    fn has_keyboard_pattern(password: &str) -> bool {
        // Check for simple keyboard patterns
        let patterns = ["qwerty", "asdf", "zxcv", "123456", "abcdef"];
        let lower_password = password.to_lowercase();
        patterns.iter().any(|&pattern| lower_password.contains(pattern))
    }
}

// ============================================================================
// AES-GCM SYMMETRIC ENCRYPTION IMPLEMENTATION
// ============================================================================

/// Concrete implementation of SymmetricEncryption using AES-256-GCM
pub struct AesGcmEncryption;

#[async_trait]
impl SymmetricEncryption for AesGcmEncryption {
    async fn encrypt(
        &self,
        plaintext: &[u8],
        key: &[u8],
    ) -> crate::Result<EncryptionResult> {
        if key.len() != 32 {
            return Err("AES-256 requires 32-byte key".into());
        }
        
        // Create cipher
        let key_array: [u8; 32] = key.try_into()
            .map_err(|_| "Invalid key size")?;
        let aes_key = Key::<Aes256Gcm>::from_slice(&key_array);
        let cipher = Aes256Gcm::new(aes_key);
        
        // Generate nonce
        let nonce_bytes: [u8; crate::NONCE_SIZE] = rand::thread_rng().gen();
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // Encrypt
        let ciphertext = cipher.encrypt(nonce, plaintext)
            .map_err(|e| format!("Encryption failed: {}", e))?;
        
        // Create metadata
        let salt: [u8; crate::SALT_SIZE] = rand::thread_rng().gen();
        let metadata = EncryptionMetadata::new(salt, nonce_bytes);
        
        Ok(EncryptionResult {
            ciphertext,
            metadata,
            verification_tag: None, // GCM includes authentication tag in ciphertext
        })
    }
    
    async fn decrypt(
        &self,
        ciphertext: &[u8],
        key: &[u8],
        metadata: &EncryptionMetadata,
    ) -> crate::Result<Vec<u8>> {
        if key.len() != 32 {
            return Err("AES-256 requires 32-byte key".into());
        }
        
        // Create cipher
        let key_array: [u8; 32] = key.try_into()
            .map_err(|_| "Invalid key size")?;
        let aes_key = Key::<Aes256Gcm>::from_slice(&key_array);
        let cipher = Aes256Gcm::new(aes_key);
        
        // Create nonce from metadata
        let nonce = Nonce::from_slice(&metadata.nonce);
        
        // Decrypt
        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|_| "Decryption failed - wrong password or corrupted data")?;
        
        Ok(plaintext)
    }
    
    fn algorithm_name(&self) -> &'static str {
        "AES-256-GCM"
    }
    
    fn key_size(&self) -> usize {
        32 // 256 bits
    }
    
    fn nonce_size(&self) -> usize {
        crate::NONCE_SIZE
    }
}

impl AesGcmEncryption {
    pub fn new() -> Self {
        Self
    }
}

// ============================================================================
// SECURE FILE OPERATIONS IMPLEMENTATION
// ============================================================================

/// Concrete implementation combining key derivation and encryption for files
pub struct SecureFileManager {
    key_derivation: Argon2KeyDerivation,
    encryption: AesGcmEncryption,
}

#[async_trait]
impl SecureFileOperations for SecureFileManager {
    async fn encrypt_file(
        &self,
        source_path: &PathBuf,
        password: &str,
        destination_path: Option<&PathBuf>,
    ) -> crate::Result<EncryptedFile> {
        // Validate password strength
        let strength = self.key_derivation.validate_password_strength(password)?;
        if !strength.is_acceptable() {
            return Err("Password does not meet security requirements".into());
        }
        
        // Read file using memory mapping for efficiency
        let file = fs::File::open(source_path)?;
        let mmap = unsafe { Mmap::map(&file)? };
        let data = &mmap[..];
        
        // Generate salt and derive key
        let salt = self.key_derivation.generate_salt()?;
        let key = self.key_derivation.derive_key(password, &salt, None)?;
        
        // Encrypt data
        let mut encryption_result = self.encryption.encrypt(data, &key).await?;
        encryption_result.metadata.salt = salt.try_into()
            .map_err(|_| "Invalid salt size")?;
        
        // Prepare output file
        let output_path = destination_path
            .map(|p| p.clone())
            .unwrap_or_else(|| source_path.with_extension("pcapng.enc"));
        
        // Write encrypted file: salt + nonce + ciphertext
        let mut encrypted_data = Vec::with_capacity(
            crate::HEADER_SIZE + encryption_result.ciphertext.len()
        );
        encrypted_data.extend_from_slice(&encryption_result.metadata.salt);
        encrypted_data.extend_from_slice(&encryption_result.metadata.nonce);
        encrypted_data.extend_from_slice(&encryption_result.ciphertext);
        
        fs::write(&output_path, encrypted_data)?;
        
        // Get file size
        let size_bytes = fs::metadata(&output_path)?.len();
        
        // Create EncryptedFile entity
        let encrypted_file = EncryptedFile::new(
            output_path.clone(),
            source_path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
                .to_string(),
            size_bytes,
        )?;
        
        // Clean up source file if different from destination
        if destination_path.is_some() || &output_path != source_path {
            fs::remove_file(source_path)?;
        }
        
        Ok(encrypted_file)
    }
    
    async fn decrypt_file(
        &self,
        encrypted_file: &EncryptedFile,
        password: &str,
        destination_path: Option<&PathBuf>,
    ) -> crate::Result<PathBuf> {
        // Read encrypted file using memory mapping
        let file = fs::File::open(&encrypted_file.path)?;
        let mmap = unsafe { Mmap::map(&file)? };
        let encrypted_data = &mmap[..];
        
        if encrypted_data.len() < crate::HEADER_SIZE {
            return Err("Invalid encrypted file format".into());
        }
        
        // Parse header
        let (salt, rest) = encrypted_data.split_at(crate::SALT_SIZE);
        let (nonce_bytes, ciphertext) = rest.split_at(crate::NONCE_SIZE);
        
        let salt_array: [u8; crate::SALT_SIZE] = salt.try_into()
            .map_err(|_| "Invalid salt size")?;
        let nonce_array: [u8; crate::NONCE_SIZE] = nonce_bytes.try_into()
            .map_err(|_| "Invalid nonce size")?;
        
        // Derive key from password
        let key = self.key_derivation.derive_key(password, &salt_array, None)?;
        
        // Create metadata for decryption
        let metadata = EncryptionMetadata::new(salt_array, nonce_array);
        
        // Decrypt data
        let plaintext = self.encryption.decrypt(ciphertext, &key, &metadata).await?;
        
        // Prepare output path
        let output_path = destination_path
            .map(|p| p.clone())
            .unwrap_or_else(|| {
                encrypted_file.path.with_file_name(&encrypted_file.decrypted_filename())
            });
        
        // Write decrypted file
        fs::write(&output_path, plaintext)?;
        
        Ok(output_path)
    }
    
    async fn verify_file_integrity(
        &self,
        encrypted_file: &EncryptedFile,
        password: &str,
    ) -> crate::Result<bool> {
        // Try to decrypt just the first few bytes to verify password/integrity
        let file = fs::File::open(&encrypted_file.path)?;
        let mmap = unsafe { Mmap::map(&file)? };
        let encrypted_data = &mmap[..];
        
        if encrypted_data.len() < crate::HEADER_SIZE {
            return Ok(false);
        }
        
        // Parse header
        let (salt, rest) = encrypted_data.split_at(crate::SALT_SIZE);
        let (nonce_bytes, ciphertext) = rest.split_at(crate::NONCE_SIZE);
        
        let salt_array: [u8; crate::SALT_SIZE] = salt.try_into()
            .map_err(|_| "Invalid salt size")?;
        let nonce_array: [u8; crate::NONCE_SIZE] = nonce_bytes.try_into()
            .map_err(|_| "Invalid nonce size")?;
        
        // Derive key
        let key = self.key_derivation.derive_key(password, &salt_array, None)?;
        let metadata = EncryptionMetadata::new(salt_array, nonce_array);
        
        // Try to decrypt - if it succeeds, integrity is good
        match self.encryption.decrypt(ciphertext, &key, &metadata).await {
            Ok(_) => Ok(true),
            Err(_) => Ok(false), // Decryption failed = bad password or corrupted data
        }
    }
    
    async fn read_metadata(&self, file_path: &PathBuf) -> crate::Result<EncryptionMetadata> {
        let file = fs::File::open(file_path)?;
        let mmap = unsafe { Mmap::map(&file)? };
        let encrypted_data = &mmap[..];
        
        if encrypted_data.len() < crate::HEADER_SIZE {
            return Err("Invalid encrypted file format".into());
        }
        
        let (salt, rest) = encrypted_data.split_at(crate::SALT_SIZE);
        let (nonce_bytes, _) = rest.split_at(crate::NONCE_SIZE);
        
        let salt_array: [u8; crate::SALT_SIZE] = salt.try_into()
            .map_err(|_| "Invalid salt size")?;
        let nonce_array: [u8; crate::NONCE_SIZE] = nonce_bytes.try_into()
            .map_err(|_| "Invalid nonce size")?;
        
        Ok(EncryptionMetadata::new(salt_array, nonce_array))
    }
}

impl SecureFileManager {
    pub fn new() -> Self {
        Self {
            key_derivation: Argon2KeyDerivation::new(),
            encryption: AesGcmEncryption::new(),
        }
    }
    
    pub fn with_custom_iterations(iterations: u32) -> Self {
        Self {
            key_derivation: Argon2KeyDerivation::new().with_iterations(iterations),
            encryption: AesGcmEncryption::new(),
        }
    }
}

// ============================================================================
// DEFAULT IMPLEMENTATIONS
// ============================================================================

impl Default for Argon2KeyDerivation {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for AesGcmEncryption {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for SecureFileManager {
    fn default() -> Self {
        Self::new()
    }
}
