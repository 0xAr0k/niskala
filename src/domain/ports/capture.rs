use std::path::PathBuf;
use async_trait::async_trait;
use crate::domain::entities::{CaptureOptions};

// ============================================================================
// CAPTURE EXECUTION PORTS
// ============================================================================

/// Port for executing network captures
/// This abstracts away the actual capture implementation (tshark, tcpdump, etc.)
#[async_trait]
pub trait CaptureExecutor {
    /// Start a live network capture
    async fn start_live_capture(
        &self,
        interface: &str,
        output_path: &PathBuf,
        options: &CaptureOptions,
    ) -> crate::Result<CaptureHandle>;

    /// Process an existing capture file
    async fn process_file_capture(
        &self,
        input_file: &PathBuf,
        output_path: &PathBuf,
        options: &CaptureOptions,
    ) -> crate::Result<CaptureHandle>;

    /// Stop a running capture
    async fn stop_capture(&self, handle: CaptureHandle) -> crate::Result<CaptureResult>;

    /// Check if capture tools are available on the system
    fn check_availability(&self) -> crate::Result<CaptureTool>;
}

/// Port for building capture commands
/// Separates command construction from execution
pub trait CaptureCommandBuilder {
    /// Build tshark command arguments
    fn build_tshark_args(
        &self,
        interface: &str,
        output_file: Option<&PathBuf>,
        options: &CaptureOptions,
    ) -> Vec<String>;

    /// Build wireshark GUI command arguments
    fn build_wireshark_args(
        &self,
        interface: &str,
        options: &CaptureOptions,
    ) -> Vec<String>;

    /// Validate command arguments before execution
    fn validate_args(&self, args: &[String]) -> crate::Result<()>;
}

// ============================================================================
// CAPTURE MONITORING PORTS
// ============================================================================

/// Port for monitoring capture progress
#[async_trait]
pub trait CaptureMonitor {
    /// Get real-time capture statistics
    async fn get_capture_stats(&self, handle: &CaptureHandle) -> crate::Result<CaptureStats>;

    /// Stream capture output in real-time
    async fn stream_output(
        &self,
        handle: &CaptureHandle,
    ) -> crate::Result<Box<dyn futures::Stream<Item = String> + Send + Unpin>>;

    /// Check if capture is still active
    async fn is_active(&self, handle: &CaptureHandle) -> bool;
}

// ============================================================================
// SUPPORTING TYPES
// ============================================================================

/// Handle to a running capture process
#[derive(Debug, Clone)]
pub struct CaptureHandle {
    pub id: String,
    pub process_id: Option<u32>,
    pub started_at: chrono::DateTime<chrono::Local>,
    pub capture_type: CaptureType,
}

/// Type of capture being performed
#[derive(Debug, Clone, PartialEq)]
pub enum CaptureType {
    Live { interface: String },
    File { input_path: PathBuf },
    Remote { host: String, port: u16 },
}

/// Result of a completed capture
#[derive(Debug)]
pub struct CaptureResult {
    pub handle: CaptureHandle,
    pub output_file: PathBuf,
    pub packets_captured: u64,
    pub bytes_captured: u64,
    pub duration: std::time::Duration,
    pub exit_code: i32,
}

/// Real-time capture statistics
#[derive(Debug, Clone)]
pub struct CaptureStats {
    pub packets_captured: u64,
    pub packets_dropped: u64,
    pub bytes_captured: u64,
    pub capture_rate_pps: f64,  // packets per second
    pub capture_rate_bps: f64,  // bytes per second
    pub elapsed_time: std::time::Duration,
}

/// Available capture tools on the system
#[derive(Debug, Clone)]
pub struct CaptureTool {
    pub tshark_available: bool,
    pub tshark_version: Option<String>,
    pub wireshark_available: bool,
    pub wireshark_version: Option<String>,
    pub tcpdump_available: bool,
}

impl CaptureHandle {
    pub fn new_live(interface: String) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            process_id: None,
            started_at: chrono::Local::now(),
            capture_type: CaptureType::Live { interface },
        }
    }

    pub fn new_file(input_path: PathBuf) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            process_id: None,
            started_at: chrono::Local::now(),
            capture_type: CaptureType::File { input_path },
        }
    }
}
