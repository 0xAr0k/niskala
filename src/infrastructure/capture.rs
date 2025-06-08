use std::path::PathBuf;
use std::collections::HashMap;
use async_trait::async_trait;
use tokio::process::Command as AsyncCommand;
use std::process::{Command, Stdio};
use std::borrow::Cow;

use crate::domain::ports::capture::*;
use crate::domain::entities::{CaptureOptions};

// ============================================================================
// TSHARK CAPTURE EXECUTOR
// ============================================================================

/// Concrete implementation of CaptureExecutor using tshark
pub struct TsharkCaptureExecutor {
    tshark_path: String,
    wireshark_path: Option<String>,
}

#[async_trait]
impl CaptureExecutor for TsharkCaptureExecutor {
    async fn start_live_capture(
        &self,
        interface: &str,
        output_path: &PathBuf,
        options: &CaptureOptions,
    ) -> crate::Result<CaptureHandle> {
        let mut handle = CaptureHandle::new_live(interface.to_string());
        
        // Build command arguments  
        let builder = TsharkCommandBuilder::new();
        let args = builder.build_tshark_args(interface, Some(output_path), options);
        
        // Convert to string references for process execution
        let args_str: Vec<&str> = args.iter().map(|s| s.as_ref()).collect();
        
        // Start the process
        let child = AsyncCommand::new(&self.tshark_path)
            .args(&args_str)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        
        // Store process ID in handle
        handle.process_id = Some(child.id().unwrap_or(0));
        
        // In a real implementation, you'd store the child process somewhere
        // for monitoring and cleanup. For now, we'll return the handle.
        
        Ok(handle)
    }

    async fn process_file_capture(
        &self,
        input_file: &PathBuf,
        output_path: &PathBuf,
        options: &CaptureOptions,
    ) -> crate::Result<CaptureHandle> {
        let handle = CaptureHandle::new_file(input_file.clone());
        
        // Build command for file processing
        let _builder = TsharkCommandBuilder::new();
        let mut args = vec![
            Cow::Borrowed("-r"),
            Cow::Owned(input_file.to_string_lossy().to_string()),
            Cow::Borrowed("-w"),
            Cow::Owned(output_path.to_string_lossy().to_string()),
        ];
        
        // Add analysis options
        if options.verbose {
            args.push(Cow::Borrowed("-v"));
        }
        if options.hex_dump {
            args.push(Cow::Borrowed("-x"));
        }
        if options.protocol_tree {
            args.push(Cow::Borrowed("-V"));
        }
        
        let args_str: Vec<&str> = args.iter().map(|s| s.as_ref()).collect();
        
        let mut child = AsyncCommand::new(&self.tshark_path)
            .args(&args_str)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        
        // Wait for completion since file processing is typically fast
        let output = child.wait_with_output().await?;
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("tshark failed: {}", stderr).into());
        }
        
        Ok(handle)
    }

    async fn stop_capture(&self, handle: CaptureHandle) -> crate::Result<CaptureResult> {
        // In a real implementation, you'd kill the process here
        if let Some(pid) = handle.process_id {
            #[cfg(unix)]
            {
                use std::process::Command;
                Command::new("kill")
                    .arg("-TERM")
                    .arg(pid.to_string())
                    .output()?;
            }
            
            #[cfg(windows)]
            {
                use std::process::Command;
                Command::new("taskkill")
                    .args(["/PID", &pid.to_string(), "/F"])
                    .output()?;
            }
        }
        
        // Create a result - in real implementation, you'd gather actual stats
        let result = CaptureResult {
            handle: handle.clone(),
            output_file: PathBuf::from("dummy_output.pcapng"), // Would be actual file
            packets_captured: 0, // Would be parsed from tshark output
            bytes_captured: 0,   // Would be parsed from tshark output
            duration: chrono::Local::now().signed_duration_since(handle.started_at).to_std().unwrap_or_default(),
            exit_code: 0,
        };
        
        Ok(result)
    }

    fn check_availability(&self) -> crate::Result<CaptureTool> {
        let mut tool = CaptureTool {
            tshark_available: false,
            tshark_version: None,
            wireshark_available: false,
            wireshark_version: None,
            tcpdump_available: false,
        };
        
        // Check tshark
        if let Ok(output) = Command::new(&self.tshark_path).arg("--version").output() {
            if output.status.success() {
                tool.tshark_available = true;
                let version_output = String::from_utf8_lossy(&output.stdout);
                tool.tshark_version = Self::parse_version(&version_output);
            }
        }
        
        // Check wireshark
        if let Some(ref wireshark_path) = self.wireshark_path {
            if let Ok(output) = Command::new(wireshark_path).arg("--version").output() {
                if output.status.success() {
                    tool.wireshark_available = true;
                    let version_output = String::from_utf8_lossy(&output.stdout);
                    tool.wireshark_version = Self::parse_version(&version_output);
                }
            }
        }
        
        // Check tcpdump
        if let Ok(output) = Command::new("tcpdump").arg("--version").output() {
            tool.tcpdump_available = output.status.success();
        }
        
        Ok(tool)
    }
}

impl TsharkCaptureExecutor {
    pub fn new() -> Self {
        Self {
            tshark_path: "tshark".to_string(),
            wireshark_path: Some("wireshark".to_string()),
        }
    }
    
    pub fn with_custom_paths(tshark_path: String, wireshark_path: Option<String>) -> Self {
        Self {
            tshark_path,
            wireshark_path,
        }
    }
    
    fn parse_version(version_output: &str) -> Option<String> {
        // Parse version from output like "TShark (Wireshark) 3.6.2"
        version_output
            .lines()
            .next()?
            .split_whitespace()
            .last()
            .map(|v| v.to_string())
    }
}

// ============================================================================
// COMMAND BUILDER IMPLEMENTATION
// ============================================================================

/// Concrete implementation of CaptureCommandBuilder for tshark/wireshark
pub struct TsharkCommandBuilder {
    default_timeout: std::time::Duration,
}

impl CaptureCommandBuilder for TsharkCommandBuilder {
    fn build_tshark_args(
        &self,
        interface: &str,
        output_file: Option<&PathBuf>,
        options: &CaptureOptions,
    ) -> Vec<String> {
        let mut args = Vec::with_capacity(16);
        
        // Interface specification
        args.push("-i".to_string());
        args.push(interface.to_string());
        
        // Output file or live output
        if let Some(file) = output_file {
            args.push("-w".to_string());
            args.push(file.to_string_lossy().to_string());
        } else {
            args.push("-l".to_string()); // Line buffered output
        }
        
        // Analysis options
        if options.verbose {
            args.push("-v".to_string());
        }
        
        if options.hex_dump {
            args.push("-x".to_string());
        }
        
        if options.protocol_tree {
            args.push("-V".to_string());
        }
        
        if let Some(ref fields) = options.custom_fields {
            args.push("-T".to_string());
            args.push("fields".to_string());
            for field in fields.split(',') {
                args.push("-e".to_string());
                args.push(field.trim().to_string());
            }
            args.push("-E".to_string());
            args.push("header=y".to_string());
        }
        
        args
    }
    
    fn build_wireshark_args(
        &self,
        interface: &str,
        _options: &CaptureOptions,
    ) -> Vec<String> {
        let mut args = Vec::with_capacity(6);
        
        args.push("-i".to_string());
        args.push(interface.to_string());
        args.push("-k".to_string()); // Start capture immediately
        
        // Note: GUI options are limited compared to tshark
        
        args
    }
    
    fn validate_args(&self, args: &[String]) -> crate::Result<()> {
        // Basic validation
        if args.is_empty() {
            return Err("No arguments provided".into());
        }
        
        // Check for interface specification
        if !args.contains(&"-i".to_string()) {
            return Err("No interface specified".into());
        }
        
        // Check for dangerous arguments
        for arg in args {
            if arg.contains("..") || arg.contains("/etc") || arg.contains("C:\\Windows") {
                return Err("Potentially dangerous argument detected".into());
            }
        }
        
        Ok(())
    }
}

impl TsharkCommandBuilder {
    pub fn new() -> Self {
        Self {
            default_timeout: std::time::Duration::from_secs(300), // 5 minutes
        }
    }
    
    pub fn with_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.default_timeout = timeout;
        self
    }
}

// ============================================================================
// CAPTURE MONITOR IMPLEMENTATION  
// ============================================================================

/// Concrete implementation for monitoring capture progress
pub struct TsharkCaptureMonitor {
    active_captures: HashMap<String, ProcessInfo>,
}

#[async_trait]
impl CaptureMonitor for TsharkCaptureMonitor {
    async fn get_capture_stats(&self, handle: &CaptureHandle) -> crate::Result<CaptureStats> {
        // In a real implementation, you'd parse tshark output for statistics
        // For now, return dummy stats
        Ok(CaptureStats {
            packets_captured: 0,
            packets_dropped: 0,
            bytes_captured: 0,
            capture_rate_pps: 0.0,
            capture_rate_bps: 0.0,
            elapsed_time: chrono::Local::now().signed_duration_since(handle.started_at).to_std().unwrap_or_default(),
        })
    }
    
    async fn stream_output(
        &self,
        _handle: &CaptureHandle,
    ) -> crate::Result<Box<dyn futures::Stream<Item = String> + Send + Unpin>> {
        // This would return a stream of tshark output lines
        // For now, return an empty stream
        use futures::stream;
        Ok(Box::new(stream::empty()))
    }
    
    async fn is_active(&self, handle: &CaptureHandle) -> bool {
        if let Some(_info) = self.active_captures.get(&handle.id) {
            // Check if process is still running
            #[cfg(unix)]
            {
                use std::process::Command;
                if let Some(pid) = handle.process_id {
                    Command::new("kill")
                        .arg("-0")
                        .arg(pid.to_string())
                        .output()
                        .map(|output| output.status.success())
                        .unwrap_or(false)
                } else {
                    false
                }
            }
            #[cfg(not(unix))]
            false
        } else {
            false
        }
    }
}

impl TsharkCaptureMonitor {
    pub fn new() -> Self {
        Self {
            active_captures: HashMap::new(),
        }
    }
}

// ============================================================================
// SUPPORTING TYPES
// ============================================================================

#[derive(Debug)]
struct ProcessInfo {
    // TODO: Implement these fields
    _process_id: u32,
    _started_at: chrono::DateTime<chrono::Local>,
    _command: String,
}

impl Default for TsharkCaptureExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for TsharkCommandBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for TsharkCaptureMonitor {
    fn default() -> Self {
        Self::new()
    }
}
