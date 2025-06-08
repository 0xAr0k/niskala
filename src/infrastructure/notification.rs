use async_trait::async_trait;
use std::io::{self, Write};
use tokio::io::{AsyncBufReadExt, BufReader};

use crate::domain::ports::notification::*;

// ============================================================================
// CONSOLE USER NOTIFICATION IMPLEMENTATION
// ============================================================================

/// Concrete implementation for console-based user notifications
pub struct ConsoleUserNotification {
    use_colors: bool,
    emoji_enabled: bool,
}

#[async_trait]
impl UserNotification for ConsoleUserNotification {
    async fn show_info(&self, message: &str) -> crate::Result<()> {
        let formatted = if self.use_colors {
            format!("\x1b[34mℹ️  {}\x1b[0m", message) // Blue
        } else if self.emoji_enabled {
            format!("ℹ️  {}", message)
        } else {
            format!("INFO: {}", message)
        };
        
        println!("{}", formatted);
        Ok(())
    }

    async fn show_warning(&self, message: &str) -> crate::Result<()> {
        let formatted = if self.use_colors {
            format!("\x1b[33m⚠️  {}\x1b[0m", message) // Yellow
        } else if self.emoji_enabled {
            format!("⚠️  {}", message)
        } else {
            format!("WARNING: {}", message)
        };
        
        eprintln!("{}", formatted);
        Ok(())
    }

    async fn show_error(&self, message: &str) -> crate::Result<()> {
        let formatted = if self.use_colors {
            format!("\x1b[31m❌ {}\x1b[0m", message) // Red
        } else if self.emoji_enabled {
            format!("❌ {}", message)
        } else {
            format!("ERROR: {}", message)
        };
        
        eprintln!("{}", formatted);
        Ok(())
    }

    async fn show_success(&self, message: &str) -> crate::Result<()> {
        let formatted = if self.use_colors {
            format!("\x1b[32m✅ {}\x1b[0m", message) // Green
        } else if self.emoji_enabled {
            format!("✅ {}", message)
        } else {
            format!("SUCCESS: {}", message)
        };
        
        println!("{}", formatted);
        Ok(())
    }

    async fn ask_confirmation(&self, message: &str) -> crate::Result<bool> {
        let prompt = if self.emoji_enabled {
            format!("❓ {} (y/N): ", message)
        } else {
            format!("{} (y/N): ", message)
        };
        
        print!("{}", prompt);
        io::stdout().flush()?;
        
        let stdin = tokio::io::stdin();
        let mut reader = BufReader::new(stdin);
        let mut input = String::new();
        
        reader.read_line(&mut input).await?;
        
        let trimmed = input.trim().to_lowercase();
        Ok(trimmed == "y" || trimmed == "yes")
    }

    async fn ask_input(&self, prompt: &str) -> crate::Result<String> {
        let formatted_prompt = if self.emoji_enabled {
            format!("📝 {}: ", prompt)
        } else {
            format!("{}: ", prompt)
        };
        
        print!("{}", formatted_prompt);
        io::stdout().flush()?;
        
        let stdin = tokio::io::stdin();
        let mut reader = BufReader::new(stdin);
        let mut input = String::new();
        
        reader.read_line(&mut input).await?;
        Ok(input.trim().to_string())
    }

    async fn ask_password(&self, prompt: &str) -> crate::Result<String> {
        let formatted_prompt = if self.emoji_enabled {
            format!("🔐 {}: ", prompt)
        } else {
            format!("{}: ", prompt)
        };
        
        print!("{}", formatted_prompt);
        io::stdout().flush()?;
        
        // Use rpassword for hidden input
        let password = rpassword::read_password()?;
        Ok(password)
    }
}

impl ConsoleUserNotification {
    pub fn new() -> Self {
        Self {
            use_colors: Self::supports_colors(),
            emoji_enabled: true,
        }
    }
    
    pub fn with_colors(mut self, use_colors: bool) -> Self {
        self.use_colors = use_colors;
        self
    }
    
    pub fn with_emoji(mut self, emoji_enabled: bool) -> Self {
        self.emoji_enabled = emoji_enabled;
        self
    }
    
    fn supports_colors() -> bool {
        // Check if terminal supports colors
        std::env::var("TERM").map_or(false, |term| {
            !term.is_empty() && term != "dumb"
        })
    }
}

// ============================================================================
// CONSOLE PROGRESS REPORTER IMPLEMENTATION
// ============================================================================

/// Concrete implementation for console-based progress reporting
pub struct ConsoleProgressReporter {
    use_colors: bool,
    show_percentage: bool,
}

#[async_trait]
impl ProgressReporter for ConsoleProgressReporter {
    async fn start_progress(&self, operation: &str, total_steps: Option<u64>) -> crate::Result<ProgressHandle> {
        let handle = ProgressHandle::new(operation.to_string(), total_steps);
        
        let message = if self.use_colors {
            format!("\x1b[34m🚀 Starting: {}\x1b[0m", operation)
        } else {
            format!("🚀 Starting: {}", operation)
        };
        
        println!("{}", message);
        Ok(handle)
    }

    async fn update_progress(&self, handle: &ProgressHandle, current: u64, message: Option<&str>) -> crate::Result<()> {
        let progress_bar = if let Some(total) = handle.total_steps {
            let percentage = (current as f64 / total as f64 * 100.0).round() as u32;
            let bar_length = 40;
            let filled = (current as f64 / total as f64 * bar_length as f64).round() as usize;
            let empty = bar_length - filled;
            
            format!("[{}{}] {}%", 
                "█".repeat(filled),
                "░".repeat(empty),
                percentage
            )
        } else {
            format!("Step {}", current)
        };
        
        let elapsed = handle.elapsed_time();
        let time_info = if elapsed.as_secs() > 0 {
            format!(" ({}s)", elapsed.as_secs())
        } else {
            String::new()
        };
        
        let full_message = if let Some(msg) = message {
            format!("{} - {}{}", progress_bar, msg, time_info)
        } else {
            format!("{}{}", progress_bar, time_info)
        };
        
        if self.use_colors {
            print!("\r\x1b[33m⏳ {}\x1b[0m", full_message);
        } else {
            print!("\r⏳ {}", full_message);
        }
        
        io::stdout().flush()?;
        Ok(())
    }

    async fn complete_progress(&self, handle: &ProgressHandle, message: Option<&str>) -> crate::Result<()> {
        let elapsed = handle.elapsed_time();
        let completion_message = message.unwrap_or("Completed");
        
        let formatted = if self.use_colors {
            format!("\r\x1b[32m✅ {}: {} ({}s)\x1b[0m\n", 
                handle.operation, completion_message, elapsed.as_secs())
        } else {
            format!("\r✅ {}: {} ({}s)\n", 
                handle.operation, completion_message, elapsed.as_secs())
        };
        
        print!("{}", formatted);
        io::stdout().flush()?;
        Ok(())
    }

    async fn cancel_progress(&self, handle: &ProgressHandle, message: Option<&str>) -> crate::Result<()> {
        let elapsed = handle.elapsed_time();
        let cancel_message = message.unwrap_or("Cancelled");
        
        let formatted = if self.use_colors {
            format!("\r\x1b[31m❌ {}: {} ({}s)\x1b[0m\n", 
                handle.operation, cancel_message, elapsed.as_secs())
        } else {
            format!("\r❌ {}: {} ({}s)\n", 
                handle.operation, cancel_message, elapsed.as_secs())
        };
        
        print!("{}", formatted);
        io::stdout().flush()?;
        Ok(())
    }
}

impl ConsoleProgressReporter {
    pub fn new() -> Self {
        Self {
            use_colors: ConsoleUserNotification::supports_colors(),
            show_percentage: true,
        }
    }
    
    pub fn with_colors(mut self, use_colors: bool) -> Self {
        self.use_colors = use_colors;
        self
    }
    
    pub fn with_percentage(mut self, show_percentage: bool) -> Self {
        self.show_percentage = show_percentage;
        self
    }
}

// ============================================================================
// FILE-BASED AUDIT LOGGER IMPLEMENTATION
// ============================================================================

/// Concrete implementation for file-based audit logging
pub struct FileAuditLogger {
    log_file_path: std::path::PathBuf,
    buffer_size: usize,
}

#[async_trait]
impl AuditLogger for FileAuditLogger {
    async fn log_security_event(&self, event: SecurityEvent) -> crate::Result<()> {
        let log_entry = format!(
            "[{}] SECURITY {} {:?} - {} (user: {}, severity: {:?})\n",
            event.timestamp.format("%Y-%m-%d %H:%M:%S"),
            event.event_type.as_str(),
            event.event_type,
            event.description,
            event.user.as_deref().unwrap_or("unknown"),
            event.severity
        );
        
        self.append_to_log(&log_entry).await
    }

    async fn log_operation_start(&self, operation: &str, details: Option<&str>) -> crate::Result<()> {
        let timestamp = chrono::Local::now();
        let log_entry = format!(
            "[{}] OPERATION_START {} {}\n",
            timestamp.format("%Y-%m-%d %H:%M:%S"),
            operation,
            details.unwrap_or("")
        );
        
        self.append_to_log(&log_entry).await
    }

    async fn log_operation_complete(&self, operation: &str, success: bool, details: Option<&str>) -> crate::Result<()> {
        let timestamp = chrono::Local::now();
        let status = if success { "SUCCESS" } else { "FAILURE" };
        let log_entry = format!(
            "[{}] OPERATION_COMPLETE {} {} {}\n",
            timestamp.format("%Y-%m-%d %H:%M:%S"),
            operation,
            status,
            details.unwrap_or("")
        );
        
        self.append_to_log(&log_entry).await
    }

    async fn log_error(&self, error: &str, context: Option<&str>) -> crate::Result<()> {
        let timestamp = chrono::Local::now();
        let log_entry = format!(
            "[{}] ERROR {} {}\n",
            timestamp.format("%Y-%m-%d %H:%M:%S"),
            error,
            context.unwrap_or("")
        );
        
        self.append_to_log(&log_entry).await
    }

    async fn log_warning(&self, warning: &str, context: Option<&str>) -> crate::Result<()> {
        let timestamp = chrono::Local::now();
        let log_entry = format!(
            "[{}] WARNING {} {}\n",
            timestamp.format("%Y-%m-%d %H:%M:%S"),
            warning,
            context.unwrap_or("")
        );
        
        self.append_to_log(&log_entry).await
    }
}

impl FileAuditLogger {
    pub fn new(log_file_path: std::path::PathBuf) -> Self {
        Self {
            log_file_path,
            buffer_size: 8192,
        }
    }
    
    pub fn with_buffer_size(mut self, buffer_size: usize) -> Self {
        self.buffer_size = buffer_size;
        self
    }
    
    async fn append_to_log(&self, entry: &str) -> crate::Result<()> {
        // Create parent directory if it doesn't exist
        if let Some(parent) = self.log_file_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        
        // Append to log file
        use tokio::fs::OpenOptions;
        use tokio::io::AsyncWriteExt;
        
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_file_path)
            .await?;
        
        file.write_all(entry.as_bytes()).await?;
        file.flush().await?;
        
        Ok(())
    }
}

// ============================================================================
// EXTENSION TRAITS FOR SECURITY EVENT TYPES
// ============================================================================

impl SecurityEventType {
    fn as_str(&self) -> &'static str {
        match self {
            SecurityEventType::AuthenticationAttempt => "AUTH_ATTEMPT",
            SecurityEventType::AuthenticationSuccess => "AUTH_SUCCESS",
            SecurityEventType::AuthenticationFailure => "AUTH_FAILURE",
            SecurityEventType::PrivilegeEscalation => "PRIVILEGE_ESCALATION",
            SecurityEventType::FileAccess => "FILE_ACCESS",
            SecurityEventType::FileEncryption => "FILE_ENCRYPTION",
            SecurityEventType::FileDecryption => "FILE_DECRYPTION",
            SecurityEventType::NetworkCapture => "NETWORK_CAPTURE",
            SecurityEventType::ConfigurationChange => "CONFIG_CHANGE",
            SecurityEventType::SystemCommand => "SYSTEM_COMMAND",
        }
    }
}

// ============================================================================
// DEFAULT IMPLEMENTATIONS
// ============================================================================

impl Default for ConsoleUserNotification {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for ConsoleProgressReporter {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for FileAuditLogger {
    fn default() -> Self {
        let log_path = std::env::temp_dir().join("niskala_audit.log");
        Self::new(log_path)
    }
}