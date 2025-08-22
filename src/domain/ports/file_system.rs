use std::path::PathBuf;
use async_trait::async_trait;

// ============================================================================
// FILE SYSTEM PORTS
// ============================================================================

/// Port for basic file system operations
/// Abstracts away the actual file system implementation
#[async_trait]
pub trait FileSystemOperations {
    /// Read file contents into memory
    async fn read_file(&self, path: &PathBuf) -> crate::Result<Vec<u8>>;

    /// Write data to file
    async fn write_file(&self, path: &PathBuf, data: &[u8]) -> crate::Result<()>;

    /// Append data to existing file
    async fn append_file(&self, path: &PathBuf, data: &[u8]) -> crate::Result<()>;

    /// Delete file
    async fn delete_file(&self, path: &PathBuf) -> crate::Result<()>;

    /// Copy file from source to destination
    async fn copy_file(&self, source: &PathBuf, destination: &PathBuf) -> crate::Result<()>;

    /// Move/rename file
    async fn move_file(&self, source: &PathBuf, destination: &PathBuf) -> crate::Result<()>;

    /// Check if file exists
    async fn file_exists(&self, path: &PathBuf) -> bool;

    /// Get file metadata
    async fn get_file_metadata(&self, path: &PathBuf) -> crate::Result<FileMetadata>;
}

/// Port for memory-mapped file operations (for large files)
#[async_trait]
pub trait MemoryMappedFileOperations {
    /// Create memory-mapped view of file for reading
    async fn map_file_readonly(&self, path: &PathBuf) -> crate::Result<Box<dyn MappedFile>>;

    /// Create memory-mapped view of file for writing
    async fn map_file_readwrite(&self, path: &PathBuf, size: usize) -> crate::Result<Box<dyn MappedFile>>;

    /// Check if memory mapping is supported
    fn supports_memory_mapping(&self) -> bool;
}

/// Port for directory operations
#[async_trait]
pub trait DirectoryOperations {
    /// Create directory and all parent directories
    async fn create_dir_all(&self, path: &PathBuf) -> crate::Result<()>;

    /// Remove directory (must be empty)
    async fn remove_dir(&self, path: &PathBuf) -> crate::Result<()>;

    /// Remove directory and all contents
    async fn remove_dir_all(&self, path: &PathBuf) -> crate::Result<()>;

    /// List directory contents
    async fn list_dir(&self, path: &PathBuf) -> crate::Result<Vec<DirEntry>>;

    /// Check if directory exists
    async fn dir_exists(&self, path: &PathBuf) -> bool;

    /// Get directory size (recursive)
    async fn get_dir_size(&self, path: &PathBuf) -> crate::Result<u64>;
}

/// Port for path operations and utilities
pub trait PathOperations {
    /// Get secure storage directory for the application
    fn get_secure_storage_path(&self) -> crate::Result<PathBuf>;

    /// Get temporary directory
    fn get_temp_dir(&self) -> PathBuf;

    /// Generate unique temporary file path
    fn generate_temp_file_path(&self, extension: Option<&str>) -> PathBuf;

    /// Validate path security (prevent directory traversal)
    fn validate_path_security(&self, path: &PathBuf) -> crate::Result<()>;

    /// Resolve relative paths to absolute
    fn resolve_absolute_path(&self, path: &PathBuf) -> crate::Result<PathBuf>;

    /// Get file extension
    fn get_file_extension(&self, path: &PathBuf) -> Option<String>;

    /// Change file extension
    fn with_extension(&self, path: &PathBuf, extension: &str) -> PathBuf;
}

// ============================================================================
// SUPPORTING TYPES
// ============================================================================

/// File metadata information
#[derive(Debug, Clone)]
pub struct FileMetadata {
    pub size: u64,
    pub created: chrono::DateTime<chrono::Local>,
    pub modified: chrono::DateTime<chrono::Local>,
    pub accessed: Option<chrono::DateTime<chrono::Local>>,
    pub is_readonly: bool,
    pub file_type: FileType,
    pub permissions: FilePermissions,
}

/// Type of file system entry
#[derive(Debug, Clone, PartialEq)]
pub enum FileType {
    RegularFile,
    Directory,
    SymbolicLink,
    Other,
}

/// File permissions (cross-platform representation)
#[derive(Debug, Clone)]
pub struct FilePermissions {
    pub owner_read: bool,
    pub owner_write: bool,
    pub owner_execute: bool,
    pub group_read: bool,
    pub group_write: bool,
    pub group_execute: bool,
    pub other_read: bool,
    pub other_write: bool,
    pub other_execute: bool,
}

/// Directory entry information
#[derive(Debug, Clone)]
pub struct DirEntry {
    pub path: PathBuf,
    pub name: String,
    pub file_type: FileType,
    pub size: Option<u64>,
    pub modified: Option<chrono::DateTime<chrono::Local>>,
}

/// Trait for memory-mapped file access
pub trait MappedFile: Send + Sync {
    /// Get read-only view of mapped data
    fn as_slice(&self) -> &[u8];

    /// Get mutable view of mapped data (if writable)
    fn as_mut_slice(&mut self) -> crate::Result<&mut [u8]>;

    /// Flush changes to disk
    fn flush(&self) -> crate::Result<()>;

    /// Get size of mapped region
    fn len(&self) -> usize;

    /// Check if mapping is empty
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl FilePermissions {
    pub fn readonly() -> Self {
        Self {
            owner_read: true,
            owner_write: false,
            owner_execute: false,
            group_read: true,
            group_write: false,
            group_execute: false,
            other_read: true,
            other_write: false,
            other_execute: false,
        }
    }

    pub fn read_write() -> Self {
        Self {
            owner_read: true,
            owner_write: true,
            owner_execute: false,
            group_read: false,
            group_write: false,
            group_execute: false,
            other_read: false,
            other_write: false,
            other_execute: false,
        }
    }

    pub fn is_writable(&self) -> bool {
        self.owner_write
    }
}