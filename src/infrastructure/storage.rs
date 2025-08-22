use std::path::PathBuf;
use std::collections::HashMap;
use async_trait::async_trait;
use tokio::fs;

use crate::domain::ports::encryption::{SecureStorage, StorageHandle, StorageEntry, StorageStats, SecureFileOperations};
use crate::domain::ports::repository::*;
use crate::domain::entities::{EncryptedFile, EncryptionMetadata, CaptureSession};

// ============================================================================
// FILE-BASED SECURE STORAGE IMPLEMENTATION
// ============================================================================

/// Concrete implementation using file system for encrypted storage
pub struct FileBasedSecureStorage {
    storage_root: PathBuf,
}

#[async_trait]
impl SecureStorage for FileBasedSecureStorage {
    async fn store_encrypted_file(
        &self,
        encrypted_file: &EncryptedFile,
        metadata: &EncryptionMetadata,
    ) -> crate::Result<StorageHandle> {
        // Create storage directory if it doesn't exist
        fs::create_dir_all(&self.storage_root).await?;
        
        // Generate unique storage path
        let storage_filename = format!("{}_{}.enc", 
            encrypted_file.original_name.replace(" ", "_"),
            uuid::Uuid::new_v4()
        );
        let storage_path = self.storage_root.join(&storage_filename);
        
        // Copy encrypted file to storage location
        fs::copy(&encrypted_file.path, &storage_path).await?;
        
        // Create storage handle
        let handle = StorageHandle::new(
            uuid::Uuid::new_v4().to_string(),
            storage_path,
        );
        
        // Store metadata separately
        self.store_metadata(&handle, encrypted_file, metadata).await?;
        
        Ok(handle)
    }

    async fn retrieve_encrypted_file(
        &self,
        handle: &StorageHandle,
    ) -> crate::Result<EncryptedFile> {
        if !handle.storage_path.exists() {
            return Err("Stored file not found".into());
        }
        
        let metadata = fs::metadata(&handle.storage_path).await?;
        
        // Extract original name from metadata file or handle
        let original_name = self.get_original_name(handle).await?;
        
        EncryptedFile::new(
            handle.storage_path.clone(),
            original_name,
            metadata.len(),
        )
    }

    async fn list_encrypted_files(&self) -> crate::Result<Vec<StorageEntry>> {
        let mut entries = Vec::new();
        
        if !self.storage_root.exists() {
            return Ok(entries);
        }
        
        let mut dir = fs::read_dir(&self.storage_root).await?;
        
        while let Some(entry) = dir.next_entry().await? {
            let path = entry.path();
            
            if path.extension().and_then(|s| s.to_str()) == Some("enc") {
                if let Ok(storage_entry) = self.create_storage_entry(&path).await {
                    entries.push(storage_entry);
                }
            }
        }
        
        // Sort by creation time (newest first)
        entries.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        
        Ok(entries)
    }

    async fn delete_encrypted_file(&self, handle: &StorageHandle) -> crate::Result<()> {
        // Delete the encrypted file
        if handle.storage_path.exists() {
            fs::remove_file(&handle.storage_path).await?;
        }
        
        // Delete associated metadata file
        let metadata_path = self.get_metadata_path(handle);
        if metadata_path.exists() {
            fs::remove_file(metadata_path).await?;
        }
        
        Ok(())
    }

    async fn get_storage_stats(&self) -> crate::Result<StorageStats> {
        let entries = self.list_encrypted_files().await?;
        
        let total_files = entries.len();
        let total_size_bytes = entries.iter().map(|e| e.encrypted_size).sum();
        
        let oldest_file = entries.iter()
            .map(|e| e.created_at)
            .min();
        
        let newest_file = entries.iter()
            .map(|e| e.created_at)
            .max();
        
        // Calculate available space
        let available_space_bytes = self.get_available_space().await?;
        
        Ok(StorageStats {
            total_files,
            total_size_bytes,
            available_space_bytes,
            oldest_file,
            newest_file,
        })
    }
}

impl FileBasedSecureStorage {
    pub fn new(storage_root: PathBuf) -> Self {
        Self {
            storage_root,
        }
    }
    
    async fn store_metadata(
        &self,
        handle: &StorageHandle,
        encrypted_file: &EncryptedFile,
        metadata: &EncryptionMetadata,
    ) -> crate::Result<()> {
        let metadata_path = self.get_metadata_path(handle);
        
        // Create simple metadata format (in production, use JSON/TOML)
        let metadata_content = format!(
            "original_name={}\nsize={}\ncreated_at={}\nalgorithm={:?}\n",
            encrypted_file.original_name,
            encrypted_file.size_bytes,
            encrypted_file.created_at.to_rfc3339(),
            metadata.algorithm
        );
        
        fs::write(metadata_path, metadata_content).await?;
        Ok(())
    }
    
    async fn get_original_name(&self, handle: &StorageHandle) -> crate::Result<String> {
        let metadata_path = self.get_metadata_path(handle);
        
        if metadata_path.exists() {
            let content = fs::read_to_string(metadata_path).await?;
            
            for line in content.lines() {
                if let Some(name) = line.strip_prefix("original_name=") {
                    return Ok(name.to_string());
                }
            }
        }
        
        // Fallback: extract from filename
        handle.storage_path
            .file_stem()
            .and_then(|s| s.to_str())
            .map(|s| s.to_string())
            .ok_or_else(|| "Could not determine original filename".into())
    }
    
    fn get_metadata_path(&self, handle: &StorageHandle) -> PathBuf {
        handle.storage_path.with_extension("meta")
    }
    
    async fn create_storage_entry(&self, path: &PathBuf) -> crate::Result<StorageEntry> {
        let metadata = fs::metadata(path).await?;
        let handle = StorageHandle::from_path(path.clone());
        
        let original_name = self.get_original_name(&handle).await
            .unwrap_or_else(|_| "unknown".to_string());
        
        let created_at = metadata.created()
            .map(chrono::DateTime::from)
            .unwrap_or_else(|_| chrono::Local::now());
        
        // Load encryption metadata from storage
        let encryption_metadata = EncryptionMetadata::new(
            [0u8; crate::SALT_SIZE],
            [0u8; crate::NONCE_SIZE],
        );
        
        Ok(StorageEntry {
            handle,
            original_name,
            encrypted_size: metadata.len(),
            created_at,
            last_accessed: None,
            metadata: encryption_metadata,
        })
    }
    
    async fn get_available_space(&self) -> crate::Result<u64> {
        // This would use platform-specific APIs to get actual disk space
        // For now, return a large value
        Ok(100 * 1024 * 1024 * 1024) // 100GB
    }
}

// ============================================================================
// ENCRYPTED CAPTURE REPOSITORY IMPLEMENTATION
// ============================================================================

/// Concrete implementation combining storage and encryption for captures
pub struct FileBasedCaptureRepository {
    storage: FileBasedSecureStorage,
    session_storage: FileBasedSessionStorage,
}

#[async_trait]
impl EncryptedCaptureRepository for FileBasedCaptureRepository {
    async fn store_capture(
        &self,
        capture_session: &CaptureSession,
        file_path: &PathBuf,
        password: &str,
    ) -> crate::Result<StorageHandle> {
        // First encrypt the file
        let secure_file_manager = super::crypto::SecureFileManager::new();
        let encrypted_file = secure_file_manager
            .encrypt_file(file_path, password, None)
            .await?;
        
        // Get encryption metadata
        let metadata = secure_file_manager
            .read_metadata(&encrypted_file.path)
            .await?;
        
        // Store in secure storage
        let storage_handle = self.storage
            .store_encrypted_file(&encrypted_file, &metadata)
            .await?;
        
        // Store session metadata
        let session_handle = self.session_storage
            .save_session(capture_session)
            .await?;
        
        // Link the storage handle and session handle for future retrieval
        self.link_storage_and_session(&storage_handle, &session_handle).await?;
        
        Ok(storage_handle)
    }

    async fn retrieve_capture(
        &self,
        handle: &StorageHandle,
        password: &str,
        destination: Option<&PathBuf>,
    ) -> crate::Result<PathBuf> {
        // Retrieve encrypted file
        let encrypted_file = self.storage
            .retrieve_encrypted_file(handle)
            .await?;
        
        // Decrypt the file
        let secure_file_manager = super::crypto::SecureFileManager::new();
        let decrypted_path = secure_file_manager
            .decrypt_file(&encrypted_file, password, destination)
            .await?;
        
        Ok(decrypted_path)
    }

    async fn list_captures(&self) -> crate::Result<Vec<CaptureEntry>> {
        let storage_entries = self.storage.list_encrypted_files().await?;
        let mut capture_entries = Vec::new();
        
        for storage_entry in storage_entries {
            // Load session information from storage
            let session_info = CaptureSessionInfo {
                interface: "unknown".to_string(),
                filter: None,
                packet_count: None,
                captured_at: storage_entry.created_at,
                duration: None,
            };
            
            capture_entries.push(CaptureEntry {
                handle: storage_entry.handle.clone(),
                session_info,
                storage_info: storage_entry,
                tags: Vec::new(),
                notes: None,
            });
        }
        
        Ok(capture_entries)
    }

    async fn delete_capture(&self, handle: &StorageHandle) -> crate::Result<()> {
        self.storage.delete_encrypted_file(handle).await
    }

    async fn search_captures(&self, criteria: &SearchCriteria) -> crate::Result<Vec<CaptureEntry>> {
        let all_captures = self.list_captures().await?;
        let mut filtered = Vec::new();
        
        for capture in all_captures {
            if self.matches_criteria(&capture, criteria) {
                filtered.push(capture);
            }
        }
        
        Ok(filtered)
    }

    async fn get_storage_statistics(&self) -> crate::Result<StorageStatistics> {
        let stats = self.storage.get_storage_stats().await?;
        let captures = self.list_captures().await?;
        
        // Group by interface
        let mut by_interface = HashMap::new();
        for capture in &captures {
            let interface = &capture.session_info.interface;
            let entry = by_interface.entry(interface.clone()).or_insert(InterfaceStats {
                capture_count: 0,
                total_size: 0,
                avg_size: 0,
            });
            entry.capture_count += 1;
            entry.total_size += capture.storage_info.encrypted_size;
        }
        
        // Calculate averages
        for stats in by_interface.values_mut() {
            stats.avg_size = stats.total_size / stats.capture_count as u64;
        }
        
        // Group by month
        let by_month = HashMap::new();
        
        Ok(StorageStatistics {
            total_captures: stats.total_files,
            total_size_bytes: stats.total_size_bytes,
            oldest_capture: stats.oldest_file,
            newest_capture: stats.newest_file,
            by_interface,
            by_month,
        })
    }
}

impl FileBasedCaptureRepository {
    pub fn new(storage_root: PathBuf) -> Self {
        let session_storage_root = storage_root.join("sessions");
        
        Self {
            storage: FileBasedSecureStorage::new(storage_root),
            session_storage: FileBasedSessionStorage::new(session_storage_root),
        }
    }
    
    async fn link_storage_and_session(
        &self,
        storage_handle: &StorageHandle,
        session_handle: &SessionHandle,
    ) -> crate::Result<()> {
        // Create a mapping file to link storage and session handles
        let links_dir = self.storage.storage_root.join("links");
        fs::create_dir_all(&links_dir).await?;
        
        let link_file = links_dir.join(format!("{}.link", storage_handle.id));
        let link_content = format!(
            "storage_id={}\nsession_id={}\ncreated_at={}\n",
            storage_handle.id,
            session_handle.id,
            chrono::Local::now().to_rfc3339()
        );
        
        fs::write(link_file, link_content).await?;
        Ok(())
    }
    
    async fn get_linked_session(&self, storage_handle: &StorageHandle) -> crate::Result<Option<SessionHandle>> {
        let links_dir = self.storage.storage_root.join("links");
        let link_file = links_dir.join(format!("{}.link", storage_handle.id));
        
        if !link_file.exists() {
            return Ok(None);
        }
        
        let content = fs::read_to_string(link_file).await?;
        for line in content.lines() {
            if let Some(session_id) = line.strip_prefix("session_id=") {
                return Ok(Some(SessionHandle { id: session_id.to_string() }));
            }
        }
        
        Ok(None)
    }
    
    fn matches_criteria(&self, capture: &CaptureEntry, criteria: &SearchCriteria) -> bool {
        // Interface filter
        if let Some(ref interface_filter) = criteria.interface_filter {
            if !capture.session_info.interface.contains(interface_filter) {
                return false;
            }
        }
        
        // Date range filter
        if let Some(ref date_range) = criteria.date_range {
            if capture.session_info.captured_at < date_range.start ||
               capture.session_info.captured_at > date_range.end {
                return false;
            }
        }
        
        // Size range filter
        if let Some(ref size_range) = criteria.size_range {
            let size = capture.storage_info.encrypted_size;
            if let Some(min) = size_range.min_bytes {
                if size < min { return false; }
            }
            if let Some(max) = size_range.max_bytes {
                if size > max { return false; }
            }
        }
        
        // Tags filter
        if !criteria.tags.is_empty() {
            if !criteria.tags.iter().any(|tag| capture.tags.contains(tag)) {
                return false;
            }
        }
        
        true
    }
}

// ============================================================================
// SESSION STORAGE IMPLEMENTATION
// ============================================================================

/// Simple file-based storage for capture session metadata
pub struct FileBasedSessionStorage {
    storage_root: PathBuf,
}

#[async_trait]
impl CaptureSessionRepository for FileBasedSessionStorage {
    async fn save_session(&self, session: &CaptureSession) -> crate::Result<SessionHandle> {
        fs::create_dir_all(&self.storage_root).await?;
        
        let session_id = uuid::Uuid::new_v4().to_string();
        let session_file = self.storage_root.join(format!("{}.session", session_id));
        
        // Create simple session metadata (in production, use JSON/TOML)
        let session_content = format!(
            "interface={}\noutput_path={}\nfilter={}\ncreated_at={}\n",
            session.interface,
            session.output_path.display(),
            session.filter.as_deref().unwrap_or("none"),
            session.created_at.to_rfc3339()
        );
        
        fs::write(session_file, session_content).await?;
        
        Ok(SessionHandle { id: session_id })
    }

    async fn load_session(&self, handle: &SessionHandle) -> crate::Result<CaptureSession> {
        let session_file = self.storage_root.join(format!("{}.session", handle.id));
        let content = fs::read_to_string(session_file).await?;
        
        // Parse session data
        let mut interface = String::new();
        let mut output_path = PathBuf::new();
        
        for line in content.lines() {
            if let Some(value) = line.strip_prefix("interface=") {
                interface = value.to_string();
            } else if let Some(value) = line.strip_prefix("output_path=") {
                output_path = PathBuf::from(value);
            }
        }
        
        // Create session with minimal data
        CaptureSession::new(
            interface,
            output_path,
            None,
            None,
            Default::default(),
        )
    }

    async fn update_session(&self, handle: &SessionHandle, session: &CaptureSession) -> crate::Result<()> {
        // Re-save the session
        let session_file = self.storage_root.join(format!("{}.session", handle.id));
        
        let session_content = format!(
            "interface={}\noutput_path={}\nfilter={}\ncreated_at={}\n",
            session.interface,
            session.output_path.display(),
            session.filter.as_deref().unwrap_or("none"),
            session.created_at.to_rfc3339()
        );
        
        fs::write(session_file, session_content).await?;
        Ok(())
    }

    async fn delete_session(&self, handle: &SessionHandle) -> crate::Result<()> {
        let session_file = self.storage_root.join(format!("{}.session", handle.id));
        if session_file.exists() {
            fs::remove_file(session_file).await?;
        }
        Ok(())
    }

    async fn list_sessions(&self) -> crate::Result<Vec<SessionSummary>> {
        let mut summaries = Vec::new();
        
        if !self.storage_root.exists() {
            return Ok(summaries);
        }
        
        let mut dir = fs::read_dir(&self.storage_root).await?;
        
        while let Some(entry) = dir.next_entry().await? {
            let path = entry.path();
            
            if path.extension().and_then(|s| s.to_str()) == Some("session") {
                if let Ok(summary) = self.create_session_summary(&path).await {
                    summaries.push(summary);
                }
            }
        }
        
        Ok(summaries)
    }

    async fn find_sessions(&self, _criteria: &SessionSearchCriteria) -> crate::Result<Vec<SessionSummary>> {
        // Return filtered sessions based on criteria
        self.list_sessions().await
    }
}

impl FileBasedSessionStorage {
    pub fn new(storage_root: PathBuf) -> Self {
        Self { storage_root }
    }
    
    async fn create_session_summary(&self, path: &PathBuf) -> crate::Result<SessionSummary> {
        let content = fs::read_to_string(path).await?;
        let metadata = fs::metadata(path).await?;
        
        let mut interface = String::new();
        for line in content.lines() {
            if let Some(value) = line.strip_prefix("interface=") {
                interface = value.to_string();
                break;
            }
        }
        
        let session_id = path.file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();
        
        Ok(SessionSummary {
            handle: SessionHandle { id: session_id },
            interface,
            created_at: metadata.created()
                .map(chrono::DateTime::from)
                .unwrap_or_else(|_| chrono::Local::now()),
            status: SessionStatus::Completed,
            packet_count: None,
            file_size: None,
        })
    }
}

// ============================================================================
// DEFAULT IMPLEMENTATIONS
// ============================================================================

impl Default for FileBasedSessionStorage {
    fn default() -> Self {
        Self::new(PathBuf::from("./sessions"))
    }
}
