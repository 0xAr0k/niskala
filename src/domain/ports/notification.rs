use async_trait::async_trait;

// ============================================================================
// NOTIFICATION PORTS
// ============================================================================

/// Port for user notifications and feedback
#[async_trait]
pub trait UserNotification {
    /// Show informational message to user
    async fn show_info(&self, message: &str) -> crate::Result<()>;

    /// Show warning message to user
    async fn show_warning(&self, message: &str) -> crate::Result<()>;

    /// Show error message to user
    async fn show_error(&self, message: &str) -> crate::Result<()>;

    /// Show success message to user
    async fn show_success(&self, message: &str) -> crate::Result<()>;

    /// Ask user for confirmation (yes/no)
    async fn ask_confirmation(&self, message: &str) -> crate::Result<bool>;

    /// Ask user for text input
    async fn ask_input(&self, prompt: &str) -> crate::Result<String>;

    /// Ask user for password input (hidden)
    async fn ask_password(&self, prompt: &str) -> crate::Result<String>;
}

/// Port for progress reporting
#[async_trait]
pub trait ProgressReporter {
    /// Start a new progress operation
    async fn start_progress(&self, operation: &str, total_steps: Option<u64>) -> crate::Result<ProgressHandle>;

    /// Update progress
    async fn update_progress(&self, handle: &ProgressHandle, current: u64, message: Option<&str>) -> crate::Result<()>;

    /// Complete progress operation
    async fn complete_progress(&self, handle: &ProgressHandle, message: Option<&str>) -> crate::Result<()>;

    /// Cancel/abort progress operation
    async fn cancel_progress(&self, handle: &ProgressHandle, message: Option<&str>) -> crate::Result<()>;
}

/// Port for logging and audit trails
#[async_trait]
pub trait AuditLogger {
    /// Log security-relevant event
    async fn log_security_event(&self, event: SecurityEvent) -> crate::Result<()>;

    /// Log operation start
    async fn log_operation_start(&self, operation: &str, details: Option<&str>) -> crate::Result<()>;

    /// Log operation completion
    async fn log_operation_complete(&self, operation: &str, success: bool, details: Option<&str>) -> crate::Result<()>;

    /// Log error occurrence
    async fn log_error(&self, error: &str, context: Option<&str>) -> crate::Result<()>;

    /// Log warning
    async fn log_warning(&self, warning: &str, context: Option<&str>) -> crate::Result<()>;
}

// ============================================================================
// SUPPORTING TYPES
// ============================================================================

/// Handle for progress tracking
#[derive(Debug, Clone)]
pub struct ProgressHandle {
    pub id: String,
    pub operation: String,
    pub started_at: chrono::DateTime<chrono::Local>,
    pub total_steps: Option<u64>,
}

/// Security event for audit logging
#[derive(Debug, Clone)]
pub struct SecurityEvent {
    pub event_type: SecurityEventType,
    pub description: String,
    pub user: Option<String>,
    pub source_ip: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Local>,
    pub severity: SecuritySeverity,
    pub additional_data: std::collections::HashMap<String, String>,
}

/// Type of security event
#[derive(Debug, Clone, PartialEq)]
pub enum SecurityEventType {
    AuthenticationAttempt,
    AuthenticationSuccess,
    AuthenticationFailure,
    PrivilegeEscalation,
    FileAccess,
    FileEncryption,
    FileDecryption,
    NetworkCapture,
    ConfigurationChange,
    SystemCommand,
}

/// Severity of security event
#[derive(Debug, Clone, PartialEq, Ord, PartialOrd, Eq)]
pub enum SecuritySeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl ProgressHandle {
    pub fn new(operation: String, total_steps: Option<u64>) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            operation,
            started_at: chrono::Local::now(),
            total_steps,
        }
    }

    pub fn elapsed_time(&self) -> std::time::Duration {
        let now = chrono::Local::now();
        (now - self.started_at).to_std().unwrap_or_default()
    }
}

impl SecurityEvent {
    pub fn new(event_type: SecurityEventType, description: String) -> Self {
        Self {
            event_type,
            description,
            user: None,
            source_ip: None,
            timestamp: chrono::Local::now(),
            severity: SecuritySeverity::Low,
            additional_data: std::collections::HashMap::new(),
        }
    }

    pub fn with_user(mut self, user: String) -> Self {
        self.user = Some(user);
        self
    }

    pub fn with_severity(mut self, severity: SecuritySeverity) -> Self {
        self.severity = severity;
        self
    }

    pub fn with_data(mut self, key: String, value: String) -> Self {
        self.additional_data.insert(key, value);
        self
    }
}