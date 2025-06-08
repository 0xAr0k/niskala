use std::path::PathBuf;
use std::sync::Arc;

use crate::domain::ports::capture::*;
use crate::domain::ports::encryption::*;
use crate::domain::ports::file_system::*;
use crate::domain::ports::process::*;
use crate::domain::ports::validation::*;
use crate::domain::ports::repository::*;
use crate::domain::ports::notification::*;

use super::capture::*;
use super::crypto::*;
use super::file_system::*;
use super::process::*;
use super::validation::*;
use super::storage::*;
use super::notification::*;

// ============================================================================
// ADAPTER FACTORY TRAIT
// ============================================================================

/// Factory trait for creating infrastructure adapters
pub trait AdapterFactory {
    type CaptureExecutor: CaptureExecutor + Send + Sync;
    type CaptureCommandBuilder: CaptureCommandBuilder + Send + Sync;
    type CaptureMonitor: CaptureMonitor + Send + Sync;
    
    type KeyDerivation: KeyDerivation + Send + Sync;
    type SymmetricEncryption: SymmetricEncryption + Send + Sync;
    type SecureFileOperations: SecureFileOperations + Send + Sync;
    
    type FileSystemOperations: FileSystemOperations + Send + Sync;
    type MemoryMappedFileOperations: MemoryMappedFileOperations + Send + Sync;
    type DirectoryOperations: DirectoryOperations + Send + Sync;
    type PathOperations: PathOperations + Send + Sync;
    
    type ProcessExecutor: ProcessExecutor + Send + Sync;
    type SystemToolChecker: SystemToolChecker + Send + Sync;
    type NetworkInterfaceManager: NetworkInterfaceManager + Send + Sync;
    type SystemInfo: SystemInfo + Send + Sync;
    
    type CaptureConfigValidator: CaptureConfigValidator + Send + Sync;
    type EncryptionValidator: EncryptionValidator + Send + Sync;
    type SecurityValidator: SecurityValidator + Send + Sync;
    
    type EncryptedCaptureRepository: EncryptedCaptureRepository + Send + Sync;
    type CaptureSessionRepository: CaptureSessionRepository + Send + Sync;
    
    type UserNotification: UserNotification + Send + Sync;
    type ProgressReporter: ProgressReporter + Send + Sync;
    type AuditLogger: AuditLogger + Send + Sync;
    
    fn create_capture_executor(&self) -> Self::CaptureExecutor;
    fn create_capture_command_builder(&self) -> Self::CaptureCommandBuilder;
    fn create_capture_monitor(&self) -> Self::CaptureMonitor;
    
    fn create_key_derivation(&self) -> Self::KeyDerivation;
    fn create_symmetric_encryption(&self) -> Self::SymmetricEncryption;
    fn create_secure_file_operations(&self) -> Self::SecureFileOperations;
    
    fn create_file_system_operations(&self) -> Self::FileSystemOperations;
    fn create_memory_mapped_file_operations(&self) -> Self::MemoryMappedFileOperations;
    fn create_directory_operations(&self) -> Self::DirectoryOperations;
    fn create_path_operations(&self) -> Self::PathOperations;
    
    fn create_process_executor(&self) -> Self::ProcessExecutor;
    fn create_system_tool_checker(&self) -> Self::SystemToolChecker;
    fn create_network_interface_manager(&self) -> Self::NetworkInterfaceManager;
    fn create_system_info(&self) -> Self::SystemInfo;
    
    fn create_capture_config_validator(&self) -> Self::CaptureConfigValidator;
    fn create_encryption_validator(&self) -> Self::EncryptionValidator;
    fn create_security_validator(&self) -> Self::SecurityValidator;
    
    fn create_encrypted_capture_repository(&self) -> Self::EncryptedCaptureRepository;
    fn create_capture_session_repository(&self) -> Self::CaptureSessionRepository;
    
    fn create_user_notification(&self) -> Self::UserNotification;
    fn create_progress_reporter(&self) -> Self::ProgressReporter;
    fn create_audit_logger(&self) -> Self::AuditLogger;
}

// ============================================================================
// STANDARD ADAPTER FACTORY
// ============================================================================

/// Standard factory implementation using all concrete adapters
pub struct StandardAdapterFactory {
    config: FactoryConfig,
}

/// Configuration for the adapter factory
#[derive(Debug, Clone)]
pub struct FactoryConfig {
    pub app_name: String,
    pub storage_root: PathBuf,
    pub log_file_path: PathBuf,
    pub tshark_path: Option<String>,
    pub wireshark_path: Option<String>,
    pub use_colors: bool,
    pub emoji_enabled: bool,
    pub argon2_iterations: u32,
}

impl Default for FactoryConfig {
    fn default() -> Self {
        let app_name = "niskala".to_string();
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        
        Self {
            app_name: app_name.clone(),
            storage_root: home.join(format!(".{}_secure", app_name)),
            log_file_path: home.join(format!(".{}_audit.log", app_name)),
            tshark_path: None, // Use system default
            wireshark_path: None, // Use system default
            use_colors: true,
            emoji_enabled: true,
            argon2_iterations: 3,
        }
    }
}

impl AdapterFactory for StandardAdapterFactory {
    type CaptureExecutor = TsharkCaptureExecutor;
    type CaptureCommandBuilder = TsharkCommandBuilder;
    type CaptureMonitor = TsharkCaptureMonitor;
    
    type KeyDerivation = Argon2KeyDerivation;
    type SymmetricEncryption = AesGcmEncryption;
    type SecureFileOperations = SecureFileManager;
    
    type FileSystemOperations = TokioFileSystem;
    type MemoryMappedFileOperations = MemmapFileSystem;
    type DirectoryOperations = TokioDirectoryManager;
    type PathOperations = StandardPathOperations;
    
    type ProcessExecutor = TokioProcessExecutor;
    type SystemToolChecker = StandardToolChecker;
    type NetworkInterfaceManager = SystemNetworkManager;
    type SystemInfo = StandardSystemInfo;
    
    type CaptureConfigValidator = StandardCaptureValidator<SystemNetworkManager, StandardSystemInfo>;
    type EncryptionValidator = StandardEncryptionValidator;
    type SecurityValidator = StandardSecurityValidator;
    
    type EncryptedCaptureRepository = FileBasedCaptureRepository;
    type CaptureSessionRepository = FileBasedSessionStorage;
    
    type UserNotification = ConsoleUserNotification;
    type ProgressReporter = ConsoleProgressReporter;
    type AuditLogger = FileAuditLogger;
    
    fn create_capture_executor(&self) -> Self::CaptureExecutor {
        if let (Some(tshark), wireshark) = (&self.config.tshark_path, &self.config.wireshark_path) {
            TsharkCaptureExecutor::with_custom_paths(tshark.clone(), wireshark.clone())
        } else {
            TsharkCaptureExecutor::new()
        }
    }
    
    fn create_capture_command_builder(&self) -> Self::CaptureCommandBuilder {
        TsharkCommandBuilder::new()
    }
    
    fn create_capture_monitor(&self) -> Self::CaptureMonitor {
        TsharkCaptureMonitor::new()
    }
    
    fn create_key_derivation(&self) -> Self::KeyDerivation {
        Argon2KeyDerivation::new().with_iterations(self.config.argon2_iterations)
    }
    
    fn create_symmetric_encryption(&self) -> Self::SymmetricEncryption {
        AesGcmEncryption::new()
    }
    
    fn create_secure_file_operations(&self) -> Self::SecureFileOperations {
        SecureFileManager::with_custom_iterations(self.config.argon2_iterations)
    }
    
    fn create_file_system_operations(&self) -> Self::FileSystemOperations {
        TokioFileSystem::with_base_path(self.config.storage_root.clone())
    }
    
    fn create_memory_mapped_file_operations(&self) -> Self::MemoryMappedFileOperations {
        MemmapFileSystem::new()
    }
    
    fn create_directory_operations(&self) -> Self::DirectoryOperations {
        TokioDirectoryManager::with_base_path(self.config.storage_root.clone())
    }
    
    fn create_path_operations(&self) -> Self::PathOperations {
        StandardPathOperations::new(self.config.app_name.clone())
    }
    
    fn create_process_executor(&self) -> Self::ProcessExecutor {
        TokioProcessExecutor::new()
    }
    
    fn create_system_tool_checker(&self) -> Self::SystemToolChecker {
        StandardToolChecker::new()
    }
    
    fn create_network_interface_manager(&self) -> Self::NetworkInterfaceManager {
        SystemNetworkManager::new()
    }
    
    fn create_system_info(&self) -> Self::SystemInfo {
        StandardSystemInfo
    }
    
    fn create_capture_config_validator(&self) -> Self::CaptureConfigValidator {
        StandardCaptureValidator::new(
            self.create_network_interface_manager(),
            self.create_system_info(),
        )
    }
    
    fn create_encryption_validator(&self) -> Self::EncryptionValidator {
        StandardEncryptionValidator::new()
    }
    
    fn create_security_validator(&self) -> Self::SecurityValidator {
        StandardSecurityValidator::new()
    }
    
    fn create_encrypted_capture_repository(&self) -> Self::EncryptedCaptureRepository {
        FileBasedCaptureRepository::new(self.config.storage_root.clone())
    }
    
    fn create_capture_session_repository(&self) -> Self::CaptureSessionRepository {
        FileBasedSessionStorage::new(self.config.storage_root.join("sessions"))
    }
    
    fn create_user_notification(&self) -> Self::UserNotification {
        ConsoleUserNotification::new()
            .with_colors(self.config.use_colors)
            .with_emoji(self.config.emoji_enabled)
    }
    
    fn create_progress_reporter(&self) -> Self::ProgressReporter {
        ConsoleProgressReporter::new()
            .with_colors(self.config.use_colors)
    }
    
    fn create_audit_logger(&self) -> Self::AuditLogger {
        FileAuditLogger::new(self.config.log_file_path.clone())
    }
}

impl StandardAdapterFactory {
    pub fn new(config: FactoryConfig) -> Self {
        Self { config }
    }
    
    pub fn with_default_config() -> Self {
        Self::new(FactoryConfig::default())
    }
}

// ============================================================================
// DEPENDENCY CONTAINER
// ============================================================================

/// Container holding all infrastructure dependencies
pub struct DependencyContainer {
    factory: StandardAdapterFactory,
    
    // Cached instances (using Arc for shared ownership)
    capture_executor: Option<Arc<dyn CaptureExecutor + Send + Sync>>,
    secure_file_operations: Option<Arc<dyn SecureFileOperations + Send + Sync>>,
    user_notification: Option<Arc<dyn UserNotification + Send + Sync>>,
    progress_reporter: Option<Arc<dyn ProgressReporter + Send + Sync>>,
    audit_logger: Option<Arc<dyn AuditLogger + Send + Sync>>,
    encrypted_capture_repository: Option<Arc<dyn EncryptedCaptureRepository + Send + Sync>>,
}

impl DependencyContainer {
    pub fn new(factory: StandardAdapterFactory) -> Self {
        Self {
            factory,
            capture_executor: None,
            secure_file_operations: None,
            user_notification: None,
            progress_reporter: None,
            audit_logger: None,
            encrypted_capture_repository: None,
        }
    }
    
    pub fn with_default_config() -> Self {
        Self::new(StandardAdapterFactory::with_default_config())
    }
    
    // Lazy initialization with caching
    pub fn capture_executor(&mut self) -> Arc<dyn CaptureExecutor + Send + Sync> {
        if self.capture_executor.is_none() {
            self.capture_executor = Some(Arc::new(self.factory.create_capture_executor()));
        }
        self.capture_executor.as_ref().unwrap().clone()
    }
    
    pub fn secure_file_operations(&mut self) -> Arc<dyn SecureFileOperations + Send + Sync> {
        if self.secure_file_operations.is_none() {
            self.secure_file_operations = Some(Arc::new(self.factory.create_secure_file_operations()));
        }
        self.secure_file_operations.as_ref().unwrap().clone()
    }
    
    pub fn user_notification(&mut self) -> Arc<dyn UserNotification + Send + Sync> {
        if self.user_notification.is_none() {
            self.user_notification = Some(Arc::new(self.factory.create_user_notification()));
        }
        self.user_notification.as_ref().unwrap().clone()
    }
    
    pub fn progress_reporter(&mut self) -> Arc<dyn ProgressReporter + Send + Sync> {
        if self.progress_reporter.is_none() {
            self.progress_reporter = Some(Arc::new(self.factory.create_progress_reporter()));
        }
        self.progress_reporter.as_ref().unwrap().clone()
    }
    
    pub fn audit_logger(&mut self) -> Arc<dyn AuditLogger + Send + Sync> {
        if self.audit_logger.is_none() {
            self.audit_logger = Some(Arc::new(self.factory.create_audit_logger()));
        }
        self.audit_logger.as_ref().unwrap().clone()
    }
    
    pub fn encrypted_capture_repository(&mut self) -> Arc<dyn EncryptedCaptureRepository + Send + Sync> {
        if self.encrypted_capture_repository.is_none() {
            self.encrypted_capture_repository = Some(Arc::new(self.factory.create_encrypted_capture_repository()));
        }
        self.encrypted_capture_repository.as_ref().unwrap().clone()
    }
    
    // Create new instances (not cached)
    pub fn create_capture_config_validator(&self) -> impl CaptureConfigValidator + Send + Sync {
        self.factory.create_capture_config_validator()
    }
    
    pub fn create_encryption_validator(&self) -> impl EncryptionValidator + Send + Sync {
        self.factory.create_encryption_validator()
    }
    
    pub fn create_security_validator(&self) -> impl SecurityValidator + Send + Sync {
        self.factory.create_security_validator()
    }
}

// ============================================================================
// BUILDER PATTERN FOR FACTORY CONFIG
// ============================================================================

impl FactoryConfig {
    pub fn builder() -> FactoryConfigBuilder {
        FactoryConfigBuilder::new()
    }
}

pub struct FactoryConfigBuilder {
    config: FactoryConfig,
}

impl FactoryConfigBuilder {
    pub fn new() -> Self {
        Self {
            config: FactoryConfig::default(),
        }
    }
    
    pub fn app_name(mut self, name: impl Into<String>) -> Self {
        self.config.app_name = name.into();
        self
    }
    
    pub fn storage_root(mut self, path: impl Into<PathBuf>) -> Self {
        self.config.storage_root = path.into();
        self
    }
    
    pub fn log_file_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.config.log_file_path = path.into();
        self
    }
    
    pub fn tshark_path(mut self, path: impl Into<String>) -> Self {
        self.config.tshark_path = Some(path.into());
        self
    }
    
    pub fn wireshark_path(mut self, path: impl Into<String>) -> Self {
        self.config.wireshark_path = Some(path.into());
        self
    }
    
    pub fn disable_colors(mut self) -> Self {
        self.config.use_colors = false;
        self
    }
    
    pub fn disable_emoji(mut self) -> Self {
        self.config.emoji_enabled = false;
        self
    }
    
    pub fn argon2_iterations(mut self, iterations: u32) -> Self {
        self.config.argon2_iterations = iterations;
        self
    }
    
    pub fn build(self) -> FactoryConfig {
        self.config
    }
}

impl Default for FactoryConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// CONVENIENCE FUNCTIONS
// ============================================================================

/// Create a dependency container with default configuration
pub fn create_default_container() -> DependencyContainer {
    DependencyContainer::with_default_config()
}

/// Create a dependency container with custom configuration
pub fn create_container_with_config(config: FactoryConfig) -> DependencyContainer {
    let factory = StandardAdapterFactory::new(config);
    DependencyContainer::new(factory)
}

/// Create a minimal container for testing
#[cfg(test)]
pub fn create_test_container() -> DependencyContainer {
    let config = FactoryConfig::builder()
        .app_name("niskala_test")
        .storage_root(std::env::temp_dir().join("niskala_test"))
        .log_file_path(std::env::temp_dir().join("niskala_test.log"))
        .disable_colors()
        .disable_emoji()
        .build();
    
    create_container_with_config(config)
}