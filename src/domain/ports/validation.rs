use async_trait::async_trait;
use std::path::PathBuf;

// ============================================================================
// VALIDATION PORTS
// ============================================================================

/// Port for validating capture configurations
#[async_trait]  
pub trait CaptureConfigValidator {
    /// Validate interface name and availability
    async fn validate_interface(&self, interface: &str) -> crate::Result<ValidationResult>;

    /// Validate capture filter syntax
    async fn validate_filter(&self, filter: &str) -> crate::Result<ValidationResult>;

    /// Validate output path permissions and space
    async fn validate_output_path(&self, path: &PathBuf) -> crate::Result<ValidationResult>;

    /// Validate complete capture configuration
    async fn validate_capture_config(&self, config: &CaptureValidationConfig) -> crate::Result<ValidationSummary>;
}

/// Port for validating encryption settings
pub trait EncryptionValidator {
    /// Validate password strength and complexity
    fn validate_password(&self, password: &str) -> ValidationResult;

    /// Validate file encryption parameters
    fn validate_encryption_params(&self, params: &EncryptionParams) -> ValidationResult;

    /// Check if file can be safely encrypted (not system files, etc.)
    fn validate_file_for_encryption(&self, path: &PathBuf) -> ValidationResult;
}

/// Port for security validation
pub trait SecurityValidator {
    /// Check for privilege escalation requirements
    fn validate_privileges(&self, operation: SecurityOperation) -> ValidationResult;

    /// Validate file path for security (prevent directory traversal)
    fn validate_path_security(&self, path: &PathBuf) -> ValidationResult;

    /// Check for potentially dangerous operations
    fn validate_operation_safety(&self, operation: &str, args: &[String]) -> ValidationResult;
}

// ============================================================================
// SUPPORTING TYPES
// ============================================================================

/// Validation result for a single check
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub valid: bool,
    pub severity: ValidationSeverity,
    pub message: String,
    pub suggestions: Vec<String>,
    pub error_code: Option<String>,
}

/// Severity level of validation issues
#[derive(Debug, Clone, PartialEq, Ord, PartialOrd, Eq)]
pub enum ValidationSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

/// Summary of multiple validation results
#[derive(Debug, Clone)]
pub struct ValidationSummary {
    pub overall_valid: bool,
    pub results: Vec<ValidationResult>,
    pub highest_severity: ValidationSeverity,
    pub error_count: usize,
    pub warning_count: usize,
}

/// Capture configuration for validation
#[derive(Debug, Clone)]
pub struct CaptureValidationConfig {
    pub interface: String,
    pub filter: Option<String>,
    pub output_path: PathBuf,
    pub packet_count: Option<u32>,
    pub timeout: Option<std::time::Duration>,
}

/// Encryption parameters for validation
#[derive(Debug, Clone)]
pub struct EncryptionParams {
    pub algorithm: String,
    pub key_size: usize,
    pub iterations: Option<u32>,
    pub use_hardware_acceleration: bool,
}

/// Security operation types
#[derive(Debug, Clone, PartialEq)]
pub enum SecurityOperation {
    NetworkCapture,
    FileEncryption,
    FileDecryption,
    ProcessExecution,
    DirectoryAccess,
}

impl ValidationResult {
    pub fn success(message: impl Into<String>) -> Self {
        Self {
            valid: true,
            severity: ValidationSeverity::Info,
            message: message.into(),
            suggestions: Vec::new(),
            error_code: None,
        }
    }

    pub fn warning(message: impl Into<String>) -> Self {
        Self {
            valid: true,
            severity: ValidationSeverity::Warning,
            message: message.into(),
            suggestions: Vec::new(),
            error_code: None,
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self {
            valid: false,
            severity: ValidationSeverity::Error,
            message: message.into(),
            suggestions: Vec::new(),
            error_code: None,
        }
    }

    pub fn critical(message: impl Into<String>) -> Self {
        Self {
            valid: false,
            severity: ValidationSeverity::Critical,
            message: message.into(),
            suggestions: Vec::new(),
            error_code: None,
        }
    }

    pub fn with_suggestion(mut self, suggestion: impl Into<String>) -> Self {
        self.suggestions.push(suggestion.into());
        self
    }

    pub fn with_error_code(mut self, code: impl Into<String>) -> Self {
        self.error_code = Some(code.into());
        self
    }
}

impl ValidationSummary {
    pub fn from_results(results: Vec<ValidationResult>) -> Self {
        let overall_valid = results.iter().all(|r| r.valid);
        let highest_severity = results
            .iter()
            .map(|r| &r.severity)
            .max()
            .cloned()
            .unwrap_or(ValidationSeverity::Info);
        
        let error_count = results
            .iter()
            .filter(|r| matches!(r.severity, ValidationSeverity::Error | ValidationSeverity::Critical))
            .count();
        
        let warning_count = results
            .iter()
            .filter(|r| matches!(r.severity, ValidationSeverity::Warning))
            .count();

        Self {
            overall_valid,
            results,
            highest_severity,
            error_count,
            warning_count,
        }
    }

    pub fn has_errors(&self) -> bool {
        self.error_count > 0
    }

    pub fn has_warnings(&self) -> bool {
        self.warning_count > 0
    }
}