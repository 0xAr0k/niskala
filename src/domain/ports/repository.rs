use async_trait::async_trait;
use std::path::PathBuf;
use crate::domain::entities::{CaptureSession};
use super::encryption::{StorageHandle, StorageEntry};

// ============================================================================
// REPOSITORY PORTS (Aggregate Data Operations)
// ============================================================================

/// Repository for managing encrypted capture files
/// This is an aggregate port that combines storage, encryption, and file operations
#[async_trait]
pub trait EncryptedCaptureRepository {
    /// Store a capture file with encryption
    async fn store_capture(
        &self,
        capture_session: &CaptureSession,
        file_path: &PathBuf,
        password: &str,
    ) -> crate::Result<StorageHandle>;

    /// Retrieve and decrypt a capture file
    async fn retrieve_capture(
        &self,
        handle: &StorageHandle,
        password: &str,
        destination: Option<&PathBuf>,
    ) -> crate::Result<PathBuf>;

    /// List all stored captures with metadata
    async fn list_captures(&self) -> crate::Result<Vec<CaptureEntry>>;

    /// Delete a stored capture permanently
    async fn delete_capture(&self, handle: &StorageHandle) -> crate::Result<()>;

    /// Search captures by criteria
    async fn search_captures(&self, criteria: &SearchCriteria) -> crate::Result<Vec<CaptureEntry>>;

    /// Get storage statistics
    async fn get_storage_statistics(&self) -> crate::Result<StorageStatistics>;
}

/// Repository for managing capture sessions and their metadata
#[async_trait]
pub trait CaptureSessionRepository {
    /// Save capture session metadata
    async fn save_session(&self, session: &CaptureSession) -> crate::Result<SessionHandle>;

    /// Load capture session metadata
    async fn load_session(&self, handle: &SessionHandle) -> crate::Result<CaptureSession>;

    /// Update existing session
    async fn update_session(&self, handle: &SessionHandle, session: &CaptureSession) -> crate::Result<()>;

    /// Delete session metadata
    async fn delete_session(&self, handle: &SessionHandle) -> crate::Result<()>;

    /// List all sessions with basic info
    async fn list_sessions(&self) -> crate::Result<Vec<SessionSummary>>;

    /// Find sessions by criteria
    async fn find_sessions(&self, criteria: &SessionSearchCriteria) -> crate::Result<Vec<SessionSummary>>;
}

/// Port for configuration persistence
#[async_trait]
pub trait ConfigurationRepository {
    /// Save application configuration
    async fn save_config(&self, config: &AppConfiguration) -> crate::Result<()>;

    /// Load application configuration
    async fn load_config(&self) -> crate::Result<AppConfiguration>;

    /// Update specific configuration section
    async fn update_config_section(&self, section: ConfigSection) -> crate::Result<()>;

    /// Reset configuration to defaults
    async fn reset_config(&self) -> crate::Result<()>;

    /// Backup current configuration
    async fn backup_config(&self) -> crate::Result<PathBuf>;

    /// Restore configuration from backup
    async fn restore_config(&self, backup_path: &PathBuf) -> crate::Result<()>;
}

// ============================================================================
// SUPPORTING TYPES
// ============================================================================

/// Entry for stored capture file
#[derive(Debug, Clone)]
pub struct CaptureEntry {
    pub handle: StorageHandle,
    pub session_info: CaptureSessionInfo,
    pub storage_info: StorageEntry,
    pub tags: Vec<String>,
    pub notes: Option<String>,
}

/// Basic capture session information
#[derive(Debug, Clone)]
pub struct CaptureSessionInfo {
    pub interface: String,
    pub filter: Option<String>,
    pub packet_count: Option<u32>,
    pub captured_at: chrono::DateTime<chrono::Local>,
    pub duration: Option<std::time::Duration>,
}

/// Handle for capture session metadata
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionHandle {
    pub id: String,
}

/// Summary of capture session
#[derive(Debug, Clone)]
pub struct SessionSummary {
    pub handle: SessionHandle,
    pub interface: String,
    pub created_at: chrono::DateTime<chrono::Local>,
    pub status: SessionStatus,
    pub packet_count: Option<u32>,
    pub file_size: Option<u64>,
}

/// Status of capture session
#[derive(Debug, Clone, PartialEq)]
pub enum SessionStatus {
    Active,
    Completed,
    Failed,
    Cancelled,
}

/// Search criteria for captures
#[derive(Debug, Clone, Default)]
pub struct SearchCriteria {
    pub interface_filter: Option<String>,
    pub date_range: Option<DateRange>,
    pub size_range: Option<SizeRange>,
    pub tags: Vec<String>,
    pub text_search: Option<String>,
}

/// Search criteria for sessions
#[derive(Debug, Clone, Default)]
pub struct SessionSearchCriteria {
    pub interface_filter: Option<String>,
    pub status_filter: Option<SessionStatus>,
    pub date_range: Option<DateRange>,
    pub packet_count_range: Option<CountRange>,
}

/// Date range for searches
#[derive(Debug, Clone)]
pub struct DateRange {
    pub start: chrono::DateTime<chrono::Local>,
    pub end: chrono::DateTime<chrono::Local>,
}

/// Size range for searches
#[derive(Debug, Clone)]
pub struct SizeRange {
    pub min_bytes: Option<u64>,
    pub max_bytes: Option<u64>,
}

/// Count range for searches
#[derive(Debug, Clone)]
pub struct CountRange {
    pub min: Option<u32>,
    pub max: Option<u32>,
}

/// Storage statistics
#[derive(Debug, Clone)]
pub struct StorageStatistics {
    pub total_captures: usize,
    pub total_size_bytes: u64,
    pub oldest_capture: Option<chrono::DateTime<chrono::Local>>,
    pub newest_capture: Option<chrono::DateTime<chrono::Local>>,
    pub by_interface: std::collections::HashMap<String, InterfaceStats>,
    pub by_month: std::collections::HashMap<String, MonthlyStats>,
}

/// Statistics by interface
#[derive(Debug, Clone)]
pub struct InterfaceStats {
    pub capture_count: usize,
    pub total_size: u64,
    pub avg_size: u64,
}

/// Monthly statistics
#[derive(Debug, Clone)]
pub struct MonthlyStats {
    pub capture_count: usize,
    pub total_size: u64,
}

/// Application configuration
#[derive(Debug, Clone)]
pub struct AppConfiguration {
    pub storage: StorageConfig,
    pub encryption: EncryptionConfig,
    pub capture: CaptureConfig,
    pub ui: UiConfig,
}

/// Configuration sections
#[derive(Debug, Clone)]
pub enum ConfigSection {
    Storage(StorageConfig),
    Encryption(EncryptionConfig),
    Capture(CaptureConfig),
    Ui(UiConfig),
}

/// Storage configuration
#[derive(Debug, Clone)]
pub struct StorageConfig {
    pub storage_path: PathBuf,
    pub max_storage_size: Option<u64>,
    pub auto_cleanup: bool,
    pub backup_enabled: bool,
}

/// Encryption configuration
#[derive(Debug, Clone)]
pub struct EncryptionConfig {
    pub default_algorithm: String,
    pub key_derivation_iterations: u32,
    pub require_strong_passwords: bool,
}

/// Capture configuration
#[derive(Debug, Clone)]
pub struct CaptureConfig {
    pub default_interface: Option<String>,
    pub default_filter: Option<String>,
    pub auto_encrypt: bool,
    pub max_file_size: Option<u64>,
}

/// UI configuration
#[derive(Debug, Clone)]
pub struct UiConfig {
    pub show_verbose_output: bool,
    pub auto_refresh_interval: std::time::Duration,
    pub theme: String,
}
