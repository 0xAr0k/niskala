use std::path::PathBuf;
use async_trait::async_trait;
use tokio::fs;
use tokio::io::{AsyncWriteExt};
use memmap2::Mmap;

use crate::domain::ports::file_system::*;

// ============================================================================
// STANDARD FILE SYSTEM OPERATIONS
// ============================================================================

/// Concrete implementation using tokio async filesystem operations
pub struct TokioFileSystem {
    base_path: Option<PathBuf>,
}

#[async_trait]
impl FileSystemOperations for TokioFileSystem {
    async fn read_file(&self, path: &PathBuf) -> crate::Result<Vec<u8>> {
        let resolved_path = self.resolve_path(path)?;
        let data = fs::read(&resolved_path).await?;
        Ok(data)
    }

    async fn write_file(&self, path: &PathBuf, data: &[u8]) -> crate::Result<()> {
        let resolved_path = self.resolve_path(path)?;
        
        // Create parent directories if they don't exist
        if let Some(parent) = resolved_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        
        fs::write(&resolved_path, data).await?;
        Ok(())
    }

    async fn append_file(&self, path: &PathBuf, data: &[u8]) -> crate::Result<()> {
        let resolved_path = self.resolve_path(path)?;
        
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&resolved_path)
            .await?;
        
        file.write_all(data).await?;
        file.flush().await?;
        Ok(())
    }

    async fn delete_file(&self, path: &PathBuf) -> crate::Result<()> {
        let resolved_path = self.resolve_path(path)?;
        fs::remove_file(&resolved_path).await?;
        Ok(())
    }

    async fn copy_file(&self, source: &PathBuf, destination: &PathBuf) -> crate::Result<()> {
        let source_resolved = self.resolve_path(source)?;
        let dest_resolved = self.resolve_path(destination)?;
        
        // Create parent directories for destination
        if let Some(parent) = dest_resolved.parent() {
            fs::create_dir_all(parent).await?;
        }
        
        fs::copy(&source_resolved, &dest_resolved).await?;
        Ok(())
    }

    async fn move_file(&self, source: &PathBuf, destination: &PathBuf) -> crate::Result<()> {
        let source_resolved = self.resolve_path(source)?;
        let dest_resolved = self.resolve_path(destination)?;
        
        // Create parent directories for destination
        if let Some(parent) = dest_resolved.parent() {
            fs::create_dir_all(parent).await?;
        }
        
        fs::rename(&source_resolved, &dest_resolved).await?;
        Ok(())
    }

    async fn file_exists(&self, path: &PathBuf) -> bool {
        if let Ok(resolved_path) = self.resolve_path(path) {
            resolved_path.exists()
        } else {
            false
        }
    }

    async fn get_file_metadata(&self, path: &PathBuf) -> crate::Result<FileMetadata> {
        let resolved_path = self.resolve_path(path)?;
        let metadata = fs::metadata(&resolved_path).await?;
        
        let file_type = if metadata.is_file() {
            FileType::RegularFile
        } else if metadata.is_dir() {
            FileType::Directory
        } else if metadata.is_symlink() {
            FileType::SymbolicLink
        } else {
            FileType::Other
        };
        
        // Convert system time to chrono DateTime
        let created = metadata.created()
            .map(|t| chrono::DateTime::from(t))
            .unwrap_or_else(|_| chrono::Local::now());
        
        let modified = metadata.modified()
            .map(|t| chrono::DateTime::from(t))
            .unwrap_or_else(|_| chrono::Local::now());
        
        let accessed = metadata.accessed()
            .ok()
            .map(|t| chrono::DateTime::from(t));
        
        Ok(FileMetadata {
            size: metadata.len(),
            created,
            modified,
            accessed,
            is_readonly: metadata.permissions().readonly(),
            file_type,
            permissions: Self::convert_permissions(&metadata.permissions()),
        })
    }
}

impl TokioFileSystem {
    pub fn new() -> Self {
        Self { base_path: None }
    }
    
    pub fn with_base_path(base_path: PathBuf) -> Self {
        Self {
            base_path: Some(base_path),
        }
    }
    
    fn resolve_path(&self, path: &PathBuf) -> crate::Result<PathBuf> {
        let resolved = if let Some(ref base) = self.base_path {
            if path.is_absolute() {
                path.clone()
            } else {
                base.join(path)
            }
        } else {
            path.clone()
        };
        
        // Basic security check - prevent directory traversal
        if resolved.to_string_lossy().contains("..") {
            return Err("Directory traversal attempt detected".into());
        }
        
        Ok(resolved)
    }
    
    fn convert_permissions(perms: &std::fs::Permissions) -> FilePermissions {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = perms.mode();
            FilePermissions {
                owner_read: (mode & 0o400) != 0,
                owner_write: (mode & 0o200) != 0,
                owner_execute: (mode & 0o100) != 0,
                group_read: (mode & 0o040) != 0,
                group_write: (mode & 0o020) != 0,
                group_execute: (mode & 0o010) != 0,
                other_read: (mode & 0o004) != 0,
                other_write: (mode & 0o002) != 0,
                other_execute: (mode & 0o001) != 0,
            }
        }
        
        #[cfg(not(unix))]
        {
            // Windows permissions handling
            FilePermissions {
                owner_read: true,
                owner_write: !perms.readonly(),
                owner_execute: false, // Windows doesn't have execute bit
                group_read: true,
                group_write: !perms.readonly(),
                group_execute: false,
                other_read: true,
                other_write: !perms.readonly(),
                other_execute: false,
            }
        }
    }
}

// ============================================================================
// MEMORY-MAPPED FILE OPERATIONS
// ============================================================================

/// Concrete implementation using memmap2 for large file operations
pub struct MemmapFileSystem;

#[async_trait]
impl MemoryMappedFileOperations for MemmapFileSystem {
    async fn map_file_readonly(&self, path: &PathBuf) -> crate::Result<Box<dyn MappedFile>> {
        let file = std::fs::File::open(path)?;
        let mmap = unsafe { Mmap::map(&file)? };
        Ok(Box::new(ReadOnlyMappedFile { mmap }))
    }

    async fn map_file_readwrite(&self, path: &PathBuf, size: usize) -> crate::Result<Box<dyn MappedFile>> {
        // For read-write mapping, we need to use MmapMut
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path)?;
        
        // Set file size
        file.set_len(size as u64)?;
        
        let mmap = unsafe { memmap2::MmapMut::map_mut(&file)? };
        Ok(Box::new(ReadWriteMappedFile { mmap }))
    }

    fn supports_memory_mapping(&self) -> bool {
        true // memmap2 supports all major platforms
    }
}

impl MemmapFileSystem {
    pub fn new() -> Self {
        Self
    }
}

// ============================================================================
// DIRECTORY OPERATIONS
// ============================================================================

/// Concrete implementation for directory operations
pub struct TokioDirectoryManager {
    base_path: Option<PathBuf>,
}

#[async_trait]
impl DirectoryOperations for TokioDirectoryManager {
    async fn create_dir_all(&self, path: &PathBuf) -> crate::Result<()> {
        let resolved_path = self.resolve_path(path)?;
        fs::create_dir_all(&resolved_path).await?;
        Ok(())
    }

    async fn remove_dir(&self, path: &PathBuf) -> crate::Result<()> {
        let resolved_path = self.resolve_path(path)?;
        fs::remove_dir(&resolved_path).await?;
        Ok(())
    }

    async fn remove_dir_all(&self, path: &PathBuf) -> crate::Result<()> {
        let resolved_path = self.resolve_path(path)?;
        fs::remove_dir_all(&resolved_path).await?;
        Ok(())
    }

    async fn list_dir(&self, path: &PathBuf) -> crate::Result<Vec<DirEntry>> {
        let resolved_path = self.resolve_path(path)?;
        let mut entries = Vec::new();
        let mut dir = fs::read_dir(&resolved_path).await?;
        
        while let Some(entry) = dir.next_entry().await? {
            let metadata = entry.metadata().await?;
            
            let file_type = if metadata.is_file() {
                FileType::RegularFile
            } else if metadata.is_dir() {
                FileType::Directory
            } else if metadata.is_symlink() {
                FileType::SymbolicLink
            } else {
                FileType::Other
            };
            
            let modified = metadata.modified()
                .ok()
                .map(|t| chrono::DateTime::from(t));
            
            entries.push(DirEntry {
                path: entry.path(),
                name: entry.file_name().to_string_lossy().to_string(),
                file_type,
                size: if metadata.is_file() { Some(metadata.len()) } else { None },
                modified,
            });
        }
        
        Ok(entries)
    }

    async fn dir_exists(&self, path: &PathBuf) -> bool {
        if let Ok(resolved_path) = self.resolve_path(path) {
            resolved_path.is_dir()
        } else {
            false
        }
    }

    async fn get_dir_size(&self, path: &PathBuf) -> crate::Result<u64> {
        let resolved_path = self.resolve_path(path)?;
        let size = Self::calculate_dir_size(&resolved_path).await?;
        Ok(size)
    }
}

impl TokioDirectoryManager {
    pub fn new() -> Self {
        Self { base_path: None }
    }
    
    pub fn with_base_path(base_path: PathBuf) -> Self {
        Self {
            base_path: Some(base_path),
        }
    }
    
    fn resolve_path(&self, path: &PathBuf) -> crate::Result<PathBuf> {
        let resolved = if let Some(ref base) = self.base_path {
            if path.is_absolute() {
                path.clone()
            } else {
                base.join(path)
            }
        } else {
            path.clone()
        };
        
        // Security check
        if resolved.to_string_lossy().contains("..") {
            return Err("Directory traversal attempt detected".into());
        }
        
        Ok(resolved)
    }
    
    async fn calculate_dir_size(path: &PathBuf) -> crate::Result<u64> {
        let mut total_size = 0u64;
        let mut stack = vec![path.clone()];
        
        while let Some(current_path) = stack.pop() {
            let mut dir = fs::read_dir(&current_path).await?;
            
            while let Some(entry) = dir.next_entry().await? {
                let metadata = entry.metadata().await?;
                
                if metadata.is_file() {
                    total_size += metadata.len();
                } else if metadata.is_dir() {
                    stack.push(entry.path());
                }
            }
        }
        
        Ok(total_size)
    }
}

// ============================================================================
// PATH OPERATIONS
// ============================================================================

/// Concrete implementation for path utilities
pub struct StandardPathOperations {
    app_name: String,
}

impl PathOperations for StandardPathOperations {
    fn get_secure_storage_path(&self) -> crate::Result<PathBuf> {
        let home = dirs::home_dir()
            .ok_or("Could not find home directory")?;
        
        let storage_dir = home.join(format!(".{}_secure", self.app_name));
        
        if !storage_dir.exists() {
            std::fs::create_dir_all(&storage_dir)?;
        }
        
        Ok(storage_dir)
    }

    fn get_temp_dir(&self) -> PathBuf {
        std::env::temp_dir()
    }

    fn generate_temp_file_path(&self, extension: Option<&str>) -> PathBuf {
        let mut path = self.get_temp_dir();
        let filename = format!("{}_{}", 
            self.app_name,
            uuid::Uuid::new_v4().to_string()
        );
        
        if let Some(ext) = extension {
            path.push(format!("{}.{}", filename, ext));
        } else {
            path.push(filename);
        }
        
        path
    }

    fn validate_path_security(&self, path: &PathBuf) -> crate::Result<()> {
        let path_str = path.to_string_lossy();
        
        // Check for directory traversal
        if path_str.contains("..") {
            return Err("Directory traversal attempt detected".into());
        }
        
        // Check for access to system directories
        #[cfg(unix)]
        {
            if path_str.starts_with("/etc") || 
               path_str.starts_with("/sys") || 
               path_str.starts_with("/proc") {
                return Err("Access to system directories not allowed".into());
            }
        }
        
        #[cfg(windows)]
        {
            if path_str.starts_with("C:\\Windows") || 
               path_str.starts_with("C:\\System32") {
                return Err("Access to system directories not allowed".into());
            }
        }
        
        Ok(())
    }

    fn resolve_absolute_path(&self, path: &PathBuf) -> crate::Result<PathBuf> {
        let absolute = if path.is_absolute() {
            path.clone()
        } else {
            std::env::current_dir()?.join(path)
        };
        
        Ok(absolute.canonicalize()?)
    }

    fn get_file_extension(&self, path: &PathBuf) -> Option<String> {
        path.extension()
            .and_then(|ext| ext.to_str())
            .map(|s| s.to_string())
    }

    fn with_extension(&self, path: &PathBuf, extension: &str) -> PathBuf {
        path.with_extension(extension)
    }
}

impl StandardPathOperations {
    pub fn new(app_name: String) -> Self {
        Self { app_name }
    }
}

// ============================================================================
// MAPPED FILE IMPLEMENTATIONS
// ============================================================================

struct ReadOnlyMappedFile {
    mmap: Mmap,
}

impl MappedFile for ReadOnlyMappedFile {
    fn as_slice(&self) -> &[u8] {
        &self.mmap[..]
    }

    fn as_mut_slice(&mut self) -> crate::Result<&mut [u8]> {
        Err("Read-only mapping cannot be mutated".into())
    }

    fn flush(&self) -> crate::Result<()> {
        Ok(()) // No-op for read-only
    }

    fn len(&self) -> usize {
        self.mmap.len()
    }
}

struct ReadWriteMappedFile {
    mmap: memmap2::MmapMut,
}

impl MappedFile for ReadWriteMappedFile {
    fn as_slice(&self) -> &[u8] {
        &self.mmap[..]
    }

    fn as_mut_slice(&mut self) -> crate::Result<&mut [u8]> {
        Ok(&mut self.mmap[..])
    }

    fn flush(&self) -> crate::Result<()> {
        self.mmap.flush()?;
        Ok(())
    }

    fn len(&self) -> usize {
        self.mmap.len()
    }
}

// ============================================================================
// DEFAULT IMPLEMENTATIONS
// ============================================================================

impl Default for TokioFileSystem {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for MemmapFileSystem {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for TokioDirectoryManager {
    fn default() -> Self {
        Self::new()
    }
}
