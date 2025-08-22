use std::path::PathBuf;
use std::collections::HashMap;
use async_trait::async_trait;
use tokio::process::Command as AsyncCommand;
use std::process::{Command, Stdio};
use std::borrow::Cow;
use tokio::io::{AsyncBufReadExt, BufReader};
use std::sync::Arc;

use crate::domain::ports::capture::*;
use crate::domain::entities::{CaptureOptions};
use crate::infrastructure::websocket::{WebSocketStreamer, PacketData, TerminalFormatter};

// ============================================================================
// TSHARK CAPTURE EXECUTOR
// ============================================================================

/// Concrete implementation of CaptureExecutor using tshark
pub struct TsharkCaptureExecutor {
    tshark_path: String,
    wireshark_path: Option<String>,
    websocket_streamer: Option<Arc<WebSocketStreamer>>,
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
        
        // Initialize WebSocket streamer if needed
        if options.export_format == "ws" || options.export_format == "both" {
            if let Some(ref streamer) = self.websocket_streamer {
                streamer.start().await?;
                println!("🌐 WebSocket streaming enabled on {}", options.ws_address);
            }
        }
        
        // Build command arguments  
        let builder = TsharkCommandBuilder::new();
        let mut args = builder.build_tshark_args(interface, Some(output_path), options);
        
        // For real-time output, we need to add specific tshark options
        if options.realtime_output || options.export_format != "file" {
            args.push("-l".to_string()); // Line buffered
            args.push("-T".to_string());
            args.push("text".to_string()); // Text output for parsing
        }
        
        // Convert to string references for process execution
        let args_str: Vec<&str> = args.iter().map(|s| s.as_ref()).collect();
        
        // Start the process
        let mut child = AsyncCommand::new(&self.tshark_path)
            .args(&args_str)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        
        // Store process ID in handle
        handle.process_id = Some(child.id().unwrap_or(0));
        
        // Setup real-time processing if enabled
        if options.realtime_output || options.export_format != "file" {
            if let Some(stdout) = child.stdout.take() {
                self.start_realtime_processing(stdout, options.clone()).await?;
            }
        }
        
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
        
        let child = AsyncCommand::new(&self.tshark_path)
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
        let mut packets_captured = 0u64;
        let mut bytes_captured = 0u64;
        let exit_code = 0;
        
        // Terminate the process and collect final statistics
        if let Some(pid) = handle.process_id {
            #[cfg(unix)]
            {
                use std::process::Command;
                // First try SIGTERM for graceful shutdown
                let output = Command::new("kill")
                    .arg("-TERM")
                    .arg(pid.to_string())
                    .output()?;
                
                if !output.status.success() {
                    // If SIGTERM fails, use SIGKILL
                    Command::new("kill")
                        .arg("-KILL")
                        .arg(pid.to_string())
                        .output()?;
                }
            }
            
            #[cfg(windows)]
            {
                use std::process::Command;
                let output = Command::new("taskkill")
                    .args(["/PID", &pid.to_string(), "/T"])
                    .output()?;
                
                if !output.status.success() {
                    // Force kill if normal termination fails
                    Command::new("taskkill")
                        .args(["/PID", &pid.to_string(), "/F"])
                        .output()?;
                }
            }
            
            // Give process time to write final statistics
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        }
        
        // Attempt to read capture statistics from tshark output or temp files
        if let Ok(stats) = self.extract_capture_statistics(&handle).await {
            packets_captured = stats.packets_captured;
            bytes_captured = stats.bytes_captured;
        }
        
        // Determine the actual output file path
        let output_file = match &handle.capture_type {
            CaptureType::Live { interface: _ } => {
                PathBuf::from("capture.pcapng")
            },
            CaptureType::File { input_path } => {
                input_path.clone()
            },
            CaptureType::Remote { host: _, port: _ } => {
                PathBuf::from("remote_capture.pcapng")
            },
        };
        
        let result = CaptureResult {
            handle: handle.clone(),
            output_file,
            packets_captured,
            bytes_captured,
            duration: chrono::Local::now().signed_duration_since(handle.started_at).to_std().unwrap_or_default(),
            exit_code,
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
            websocket_streamer: None,
        }
    }
    
    pub fn with_custom_paths(tshark_path: String, wireshark_path: Option<String>) -> Self {
        Self {
            tshark_path,
            wireshark_path,
            websocket_streamer: None,
        }
    }

    pub fn with_websocket(mut self, ws_address: &str) -> crate::Result<Self> {
        let addr = ws_address.parse()?;
        self.websocket_streamer = Some(Arc::new(WebSocketStreamer::new(addr)));
        Ok(self)
    }

    async fn start_realtime_processing(
        &self,
        stdout: tokio::process::ChildStdout,
        options: CaptureOptions,
    ) -> crate::Result<()> {
        let formatter = TerminalFormatter::new(&options.output_format);
        let mut reader = BufReader::new(stdout).lines();
        
        let websocket_streamer = self.websocket_streamer.clone();
        
        tokio::spawn(async move {
            while let Ok(Some(line)) = reader.next_line().await {
                if line.trim().is_empty() {
                    continue;
                }
                
                // Parse tshark output line
                if let Some(packet) = Self::parse_tshark_line(&line) {
                    // Real-time terminal output
                    if options.realtime_output {
                        println!("{}", formatter.format_packet(&packet));
                    }
                    
                    // WebSocket streaming
                    if let Some(ref streamer) = websocket_streamer {
                        if options.export_format == "ws" || options.export_format == "both" {
                            let _ = streamer.send_packet(packet);
                        }
                    }
                }
            }
        });
        
        Ok(())
    }

    fn parse_tshark_line(line: &str) -> Option<PacketData> {
        // Basic tshark text output parsing
        // Format: "  1   0.000000 192.168.1.1 → 192.168.1.2  TCP 66 [ACK] Seq=1 Ack=1 Win=1024 Len=0"
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 {
            return None;
        }

        Some(PacketData {
            timestamp: chrono::Local::now().format("%H:%M:%S%.3f").to_string(),
            source: parts.get(2)?.to_string(),
            destination: parts.get(4)?.to_string(),
            protocol: parts.get(5)?.to_string(),
            length: parts.get(6)?.parse().unwrap_or(0),
            info: parts[7..].join(" "),
            raw_data: None,
        })
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
    
    async fn extract_capture_statistics(&self, handle: &CaptureHandle) -> crate::Result<CaptureStats> {
        let mut stats = CaptureStats {
            packets_captured: 0,
            packets_dropped: 0,
            bytes_captured: 0,
            capture_rate_pps: 0.0,
            capture_rate_bps: 0.0,
            elapsed_time: std::time::Duration::from_secs(0),
        };
        
        // Try to extract statistics from output file if it exists
        match &handle.capture_type {
            CaptureType::Live { interface: _ } => {
                // For live captures, we could potentially analyze a temp file
                // but for now we'll rely on real-time monitoring
            },
            CaptureType::File { input_path } => {
                if input_path.exists() {
                    stats = self.analyze_pcap_file(input_path).await?;
                }
            },
            CaptureType::Remote { host: _, port: _ } => {
                // Remote captures would need different handling
            },
        }
        
        Ok(stats)
    }
    
    async fn analyze_pcap_file(&self, file_path: &PathBuf) -> crate::Result<CaptureStats> {
        // Use capinfos or tshark to analyze the capture file
        let output = AsyncCommand::new(&self.tshark_path)
            .args(["-r", &file_path.to_string_lossy(), "-q", "-z", "io,stat,0"])
            .output()
            .await?;
            
        if !output.status.success() {
            return Ok(CaptureStats {
                packets_captured: 0,
                packets_dropped: 0,
                bytes_captured: 0,
                capture_rate_pps: 0.0,
                capture_rate_bps: 0.0,
                elapsed_time: std::time::Duration::from_secs(0),
            });
        }
        
        let output_str = String::from_utf8_lossy(&output.stdout);
        let mut packets = 0u64;
        let mut bytes = 0u64;
        
        // Parse tshark statistics output
        for line in output_str.lines() {
            if line.contains("packets") {
                if let Some(count) = line.split_whitespace().next() {
                    packets = count.parse().unwrap_or(0);
                }
            }
            if line.contains("bytes") {
                if let Some(size) = line.split_whitespace().nth(1) {
                    bytes = size.parse().unwrap_or(0);
                }
            }
        }
        
        Ok(CaptureStats {
            packets_captured: packets,
            packets_dropped: 0,
            bytes_captured: bytes,
            capture_rate_pps: 0.0,
            capture_rate_bps: 0.0,
            elapsed_time: std::time::Duration::from_secs(0),
        })
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
        let mut stats = CaptureStats {
            packets_captured: 0,
            packets_dropped: 0,
            bytes_captured: 0,
            capture_rate_pps: 0.0,
            capture_rate_bps: 0.0,
            elapsed_time: chrono::Local::now().signed_duration_since(handle.started_at).to_std().unwrap_or_default(),
        };
        
        // Try to get real-time statistics from tshark if process is running
        if let Some(pid) = handle.process_id {
            if let Ok(tshark_stats) = self.query_tshark_statistics(pid).await {
                stats.packets_captured = tshark_stats.packets_captured;
                stats.packets_dropped = tshark_stats.packets_dropped;
                stats.bytes_captured = tshark_stats.bytes_captured;
                
                // Calculate rates
                let elapsed_secs = stats.elapsed_time.as_secs_f64();
                if elapsed_secs > 0.0 {
                    stats.capture_rate_pps = stats.packets_captured as f64 / elapsed_secs;
                    stats.capture_rate_bps = stats.bytes_captured as f64 / elapsed_secs;
                }
            }
        }
        
        Ok(stats)
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
    
    async fn query_tshark_statistics(&self, _pid: u32) -> crate::Result<CaptureStats> {
        // Real-time statistics querying would require tshark to output
        // statistics periodically or through a separate channel
        // Query real-time statistics from running tshark process
        Ok(CaptureStats {
            packets_captured: 0,
            packets_dropped: 0,
            bytes_captured: 0,
            capture_rate_pps: 0.0,
            capture_rate_bps: 0.0,
            elapsed_time: std::time::Duration::from_secs(0),
        })
    }
}

// ============================================================================
// SUPPORTING TYPES
// ============================================================================

#[derive(Debug)]
struct ProcessInfo {
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
