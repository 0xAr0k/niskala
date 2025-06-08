use std::path::PathBuf;
use async_trait::async_trait;

use crate::domain::ports::validation::*;
use crate::domain::ports::process::{NetworkInterfaceManager, SystemInfo};

// ============================================================================
// CAPTURE CONFIG VALIDATOR IMPLEMENTATION
// ============================================================================

/// Concrete implementation for validating capture configurations
pub struct StandardCaptureValidator<N, S> 
where
    N: NetworkInterfaceManager + Send + Sync,
    S: SystemInfo + Send + Sync,
{
    network_manager: N,
    system_info: S,
}

#[async_trait]
impl<N, S> CaptureConfigValidator for StandardCaptureValidator<N, S>
where
    N: NetworkInterfaceManager + Send + Sync,
    S: SystemInfo + Send + Sync,
{
    async fn validate_interface(&self, interface: &str) -> crate::Result<ValidationResult> {
        if interface.trim().is_empty() {
            return Ok(ValidationResult::error("Interface name cannot be empty"));
        }
        
        if interface == "any" {
            return Ok(ValidationResult::warning("Using 'any' interface captures all traffic")
                .with_suggestion("Consider specifying a specific interface for better performance"));
        }
        
        // Check if interface exists
        if !self.network_manager.interface_exists(interface).await {
            return Ok(ValidationResult::error(format!("Interface '{}' does not exist", interface))
                .with_suggestion("Use 'ip link show' or similar command to list available interfaces"));
        }
        
        // Validate interface for capture
        let validation = self.network_manager.validate_capture_interface(interface).await?;
        
        if !validation.valid_for_capture() {
            let issues = validation.issues.join(", ");
            return Ok(ValidationResult::error(format!("Interface cannot be used for capture: {}", issues)));
        }
        
        if !validation.warnings.is_empty() {
            let warnings = validation.warnings.join(", ");
            return Ok(ValidationResult::warning(format!("Interface warnings: {}", warnings)));
        }
        
        Ok(ValidationResult::success("Interface is valid for capture"))
    }

    async fn validate_filter(&self, filter: &str) -> crate::Result<ValidationResult> {
        if filter.trim().is_empty() {
            return Ok(ValidationResult::warning("No capture filter specified - will capture all traffic")
                .with_suggestion("Consider using a filter to reduce capture size"));
        }
        
        // Basic filter syntax validation
        if let Err(reason) = self.validate_filter_syntax(filter) {
            return Ok(ValidationResult::error(format!("Invalid filter syntax: {}", reason))
                .with_suggestion("Check tcpdump/Wireshark filter documentation"));
        }
        
        // Check for potentially performance-impacting filters
        if self.is_performance_heavy_filter(filter) {
            return Ok(ValidationResult::warning("Filter may impact capture performance")
                .with_suggestion("Consider using more specific filters"));
        }
        
        Ok(ValidationResult::success("Filter syntax is valid"))
    }

    async fn validate_output_path(&self, path: &PathBuf) -> crate::Result<ValidationResult> {
        // Check if parent directory exists
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                return Ok(ValidationResult::error("Parent directory does not exist")
                    .with_suggestion("Create the directory first or choose an existing location"));
            }
            
            // Check write permissions
            if let Ok(metadata) = std::fs::metadata(parent) {
                if metadata.permissions().readonly() {
                    return Ok(ValidationResult::error("No write permission to parent directory"));
                }
            }
        }
        
        // Check if file already exists
        if path.exists() {
            return Ok(ValidationResult::warning("Output file already exists - will be overwritten"));
        }
        
        // Check available disk space
        if let Ok(space_info) = self.get_available_disk_space(path) {
            if space_info.available_bytes < 100 * 1024 * 1024 { // Less than 100MB
                return Ok(ValidationResult::warning("Low disk space available")
                    .with_suggestion("Ensure sufficient disk space for capture"));
            }
        }
        
        // Check file extension
        if let Some(ext) = path.extension() {
            if ext != "pcap" && ext != "pcapng" {
                return Ok(ValidationResult::warning("Unusual file extension for packet capture")
                    .with_suggestion("Consider using .pcap or .pcapng extension"));
            }
        }
        
        Ok(ValidationResult::success("Output path is valid"))
    }

    async fn validate_capture_config(&self, config: &CaptureConfig) -> crate::Result<ValidationSummary> {
        let mut results = Vec::new();
        
        // Validate interface
        results.push(self.validate_interface(&config.interface).await?);
        
        // Validate filter if provided
        if let Some(ref filter) = config.filter {
            results.push(self.validate_filter(filter).await?);
        }
        
        // Validate output path
        results.push(self.validate_output_path(&config.output_path).await?);
        
        // Validate packet count
        if let Some(count) = config.packet_count {
            if count == 0 {
                results.push(ValidationResult::error("Packet count cannot be zero"));
            } else if count > 1_000_000 {
                results.push(ValidationResult::warning("Very large packet count - may result in large files")
                    .with_suggestion("Consider using a smaller count or time-based limits"));
            }
        }
        
        // Validate timeout
        if let Some(timeout) = config.timeout {
            if timeout.as_secs() == 0 {
                results.push(ValidationResult::error("Timeout cannot be zero"));
            } else if timeout.as_secs() > 3600 { // More than 1 hour
                results.push(ValidationResult::warning("Very long timeout specified")
                    .with_suggestion("Consider shorter capture periods for better manageability"));
            }
        }
        
        // Check system privileges
        if !self.system_info.has_capture_privileges() {
            results.push(ValidationResult::error("Insufficient privileges for packet capture")
                .with_suggestion("Run as administrator/root or grant CAP_NET_RAW capability"));
        }
        
        Ok(ValidationSummary::from_results(results))
    }
}

impl<N, S> StandardCaptureValidator<N, S>
where
    N: NetworkInterfaceManager + Send + Sync,
    S: SystemInfo + Send + Sync,
{
    pub fn new(network_manager: N, system_info: S) -> Self {
        Self {
            network_manager,
            system_info,
        }
    }
    
    fn validate_filter_syntax(&self, filter: &str) -> Result<(), String> {
        // Basic syntax checks for common filter patterns
        
        // Check for balanced parentheses
        let mut paren_count = 0;
        for ch in filter.chars() {
            match ch {
                '(' => paren_count += 1,
                ')' => {
                    paren_count -= 1;
                    if paren_count < 0 {
                        return Err("Unmatched closing parenthesis".to_string());
                    }
                }
                _ => {}
            }
        }
        
        if paren_count != 0 {
            return Err("Unmatched opening parenthesis".to_string());
        }
        
        // Check for basic keywords
        let keywords = ["and", "or", "not", "host", "net", "port", "src", "dst", "tcp", "udp", "icmp"];
        let lower_filter = filter.to_lowercase();
        
        // At least one keyword should be present in a meaningful filter
        if !keywords.iter().any(|&keyword| lower_filter.contains(keyword)) && !filter.chars().any(|c| c.is_ascii_digit()) {
            return Err("Filter appears to be invalid - no recognized keywords or addresses".to_string());
        }
        
        Ok(())
    }
    
    fn is_performance_heavy_filter(&self, filter: &str) -> bool {
        let heavy_patterns = [".*", ".*\\.", "host 0.0.0.0/0", "net 0.0.0.0/0"];
        let lower_filter = filter.to_lowercase();
        
        heavy_patterns.iter().any(|&pattern| lower_filter.contains(pattern))
    }
    
    fn get_available_disk_space(&self, _path: &PathBuf) -> Result<DiskSpaceInfo, std::io::Error> {
        // This would typically use platform-specific APIs
        // For now, return a dummy value
        Ok(DiskSpaceInfo {
            total_bytes: 1024 * 1024 * 1024 * 100, // 100GB
            available_bytes: 1024 * 1024 * 1024 * 50, // 50GB
        })
    }
}

// ============================================================================
// ENCRYPTION VALIDATOR IMPLEMENTATION
// ============================================================================

/// Concrete implementation for validating encryption settings
pub struct StandardEncryptionValidator;

impl EncryptionValidator for StandardEncryptionValidator {
    fn validate_password(&self, password: &str) -> ValidationResult {
        let mut issues = Vec::new();
        let mut suggestions = Vec::new();
        
        // Length validation
        if password.len() < 8 {
            issues.push("Password must be at least 8 characters long".to_string());
        } else if password.len() < 12 {
            suggestions.push("Consider using at least 12 characters for better security".to_string());
        }
        
        // Character diversity
        let has_lowercase = password.chars().any(|c| c.is_lowercase());
        let has_uppercase = password.chars().any(|c| c.is_uppercase());
        let has_digit = password.chars().any(|c| c.is_ascii_digit());
        let has_special = password.chars().any(|c| !c.is_alphanumeric());
        
        let char_types = [has_lowercase, has_uppercase, has_digit, has_special]
            .iter()
            .filter(|&&x| x)
            .count();
        
        if char_types < 2 {
            issues.push("Password must contain at least 2 different character types".to_string());
        } else if char_types < 3 {
            suggestions.push("Add more character variety for stronger security".to_string());
        }
        
        // Common patterns
        if Self::has_common_patterns(password) {
            issues.push("Password contains common patterns".to_string());
        }
        
        // Dictionary words
        if Self::has_dictionary_words(password) {
            suggestions.push("Avoid common dictionary words".to_string());
        }
        
        if !issues.is_empty() {
            ValidationResult::error("Password does not meet security requirements")
                .with_suggestion("Use a longer password with mixed character types")
        } else if !suggestions.is_empty() {
            ValidationResult::warning("Password could be stronger")
                .with_suggestion(suggestions.join("; "))
        } else {
            ValidationResult::success("Password meets security requirements")
        }
    }

    fn validate_encryption_params(&self, params: &EncryptionParams) -> ValidationResult {
        // Validate algorithm
        if params.algorithm != "AES-256-GCM" {
            return ValidationResult::error("Unsupported encryption algorithm")
                .with_suggestion("Use AES-256-GCM for best security");
        }
        
        // Validate key size
        if params.key_size < 256 {
            return ValidationResult::error("Key size too small")
                .with_suggestion("Use at least 256-bit keys");
        }
        
        // Validate iterations
        if let Some(iterations) = params.iterations {
            if iterations < 1000 {
                return ValidationResult::warning("Low iteration count may be vulnerable to attacks")
                    .with_suggestion("Use at least 10,000 iterations");
            }
        }
        
        ValidationResult::success("Encryption parameters are valid")
    }

    fn validate_file_for_encryption(&self, path: &PathBuf) -> ValidationResult {
        // Check if file exists
        if !path.exists() {
            return ValidationResult::error("File does not exist");
        }
        
        // Check if it's a regular file
        if !path.is_file() {
            return ValidationResult::error("Path is not a regular file");
        }
        
        // Check file size
        if let Ok(metadata) = std::fs::metadata(path) {
            let size = metadata.len();
            
            if size == 0 {
                return ValidationResult::error("File is empty");
            }
            
            if size > 10 * 1024 * 1024 * 1024 { // 10GB
                return ValidationResult::warning("File is very large - encryption may take significant time")
                    .with_suggestion("Consider splitting large files");
            }
        }
        
        // Check file extension
        if let Some(ext) = path.extension() {
            if ext == "enc" {
                return ValidationResult::warning("File appears to already be encrypted");
            }
        }
        
        // Check for system files
        if Self::is_system_file(path) {
            return ValidationResult::error("Cannot encrypt system files");
        }
        
        ValidationResult::success("File is safe to encrypt")
    }
}

impl StandardEncryptionValidator {
    pub fn new() -> Self {
        Self
    }
    
    fn has_common_patterns(password: &str) -> bool {
        let patterns = ["123", "abc", "qwerty", "password", "admin"];
        let lower_password = password.to_lowercase();
        patterns.iter().any(|&pattern| lower_password.contains(pattern))
    }
    
    fn has_dictionary_words(password: &str) -> bool {
        let common_words = ["password", "admin", "user", "test", "demo", "example"];
        let lower_password = password.to_lowercase();
        common_words.iter().any(|&word| lower_password.contains(word))
    }
    
    fn is_system_file(path: &PathBuf) -> bool {
        let path_str = path.to_string_lossy().to_lowercase();
        
        #[cfg(unix)]
        {
            path_str.starts_with("/etc") ||
            path_str.starts_with("/sys") ||
            path_str.starts_with("/proc") ||
            path_str.starts_with("/dev")
        }
        
        #[cfg(windows)]
        {
            path_str.starts_with("c:\\windows") ||
            path_str.starts_with("c:\\system32") ||
            path_str.contains("\\system32\\")
        }
    }
}

// ============================================================================
// SECURITY VALIDATOR IMPLEMENTATION
// ============================================================================

/// Concrete implementation for security validation
pub struct StandardSecurityValidator;

impl SecurityValidator for StandardSecurityValidator {
    fn validate_privileges(&self, operation: SecurityOperation) -> ValidationResult {
        match operation {
            SecurityOperation::NetworkCapture => {
                #[cfg(unix)]
                {
                    if unsafe { libc::geteuid() } != 0 {
                        return ValidationResult::error("Network capture requires root privileges")
                            .with_suggestion("Run with sudo or as root user");
                    }
                }
                
                ValidationResult::success("Sufficient privileges for network capture")
            }
            
            SecurityOperation::FileEncryption | SecurityOperation::FileDecryption => {
                ValidationResult::success("No special privileges required for file encryption")
            }
            
            SecurityOperation::ProcessExecution => {
                ValidationResult::success("Process execution allowed")
            }
            
            SecurityOperation::DirectoryAccess => {
                ValidationResult::success("Directory access allowed")
            }
        }
    }

    fn validate_path_security(&self, path: &PathBuf) -> ValidationResult {
        let path_str = path.to_string_lossy();
        
        // Check for directory traversal
        if path_str.contains("..") {
            return ValidationResult::error("Directory traversal attempt detected");
        }
        
        // Check for access to sensitive directories
        #[cfg(unix)]
        {
            if path_str.starts_with("/etc") || path_str.starts_with("/sys") {
                return ValidationResult::error("Access to system directories not allowed");
            }
        }
        
        #[cfg(windows)]
        {
            if path_str.to_lowercase().starts_with("c:\\windows") {
                return ValidationResult::error("Access to system directories not allowed");
            }
        }
        
        ValidationResult::success("Path is secure")
    }

    fn validate_operation_safety(&self, operation: &str, args: &[String]) -> ValidationResult {
        // Check for dangerous commands
        let dangerous_commands = ["rm", "del", "format", "fdisk", "mkfs"];
        
        if dangerous_commands.iter().any(|&cmd| operation.contains(cmd)) {
            return ValidationResult::error("Potentially dangerous operation detected");
        }
        
        // Check for dangerous arguments
        for arg in args {
            if arg.contains("..") || arg.contains("/etc") || arg.contains("C:\\Windows") {
                return ValidationResult::error("Potentially dangerous argument detected");
            }
        }
        
        ValidationResult::success("Operation appears safe")
    }
}

impl StandardSecurityValidator {
    pub fn new() -> Self {
        Self
    }
}

// ============================================================================
// SUPPORTING TYPES
// ============================================================================

#[derive(Debug)]
struct DiskSpaceInfo {
    total_bytes: u64,
    available_bytes: u64,
}

// ============================================================================
// DEFAULT IMPLEMENTATIONS
// ============================================================================

impl Default for StandardEncryptionValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for StandardSecurityValidator {
    fn default() -> Self {
        Self::new()
    }
}
