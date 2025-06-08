use std::path::PathBuf;
use std::collections::HashMap;
use async_trait::async_trait;

// ============================================================================
// PROCESS EXECUTION PORTS
// ============================================================================

/// Port for executing system processes
/// Abstracts command execution from the domain logic
#[async_trait]
pub trait ProcessExecutor {
    /// Execute command and wait for completion
    async fn execute_command(
        &self,
        command: &str,
        args: &[String],
        options: &ExecutionOptions,
    ) -> crate::Result<ProcessResult>;

    /// Start process in background and return handle
    async fn spawn_process(
        &self,
        command: &str,
        args: &[String],
        options: &ExecutionOptions,
    ) -> crate::Result<ProcessHandle>;

    /// Kill running process
    async fn kill_process(&self, handle: &ProcessHandle) -> crate::Result<()>;

    /// Check if process is still running
    async fn is_process_running(&self, handle: &ProcessHandle) -> bool;

    /// Wait for process to complete
    async fn wait_for_process(&self, handle: &ProcessHandle) -> crate::Result<ProcessResult>;
}

/// Port for streaming process output
#[async_trait]
pub trait ProcessStreaming {
    /// Stream stdout in real-time
    async fn stream_stdout(
        &self,
        handle: &ProcessHandle,
    ) -> crate::Result<Box<dyn futures::Stream<Item = String> + Send + Unpin>>;

    /// Stream stderr in real-time
    async fn stream_stderr(
        &self,
        handle: &ProcessHandle,
    ) -> crate::Result<Box<dyn futures::Stream<Item = String> + Send + Unpin>>;

    /// Send input to process stdin
    async fn send_stdin(&self, handle: &ProcessHandle, input: &str) -> crate::Result<()>;

    /// Close process stdin
    async fn close_stdin(&self, handle: &ProcessHandle) -> crate::Result<()>;
}

/// Port for system tool availability checking
pub trait SystemToolChecker {
    /// Check if a command/tool is available on the system
    fn is_tool_available(&self, tool_name: &str) -> bool;

    /// Get version of installed tool
    fn get_tool_version(&self, tool_name: &str) -> crate::Result<Option<String>>;

    /// Get path to tool executable
    fn get_tool_path(&self, tool_name: &str) -> crate::Result<Option<PathBuf>>;

    /// Check multiple tools at once
    fn check_tools(&self, tool_names: &[&str]) -> HashMap<String, ToolInfo>;
}

// ============================================================================
// NETWORK INTERFACE PORTS
// ============================================================================

/// Port for network interface operations
#[async_trait]
pub trait NetworkInterfaceManager {
    /// List all available network interfaces
    async fn list_interfaces(&self) -> crate::Result<Vec<NetworkInterface>>;

    /// Check if specific interface exists
    async fn interface_exists(&self, interface_name: &str) -> bool;

    /// Get detailed interface information
    async fn get_interface_info(&self, interface_name: &str) -> crate::Result<NetworkInterface>;

    /// Check if interface is up/active
    async fn is_interface_active(&self, interface_name: &str) -> crate::Result<bool>;

    /// Validate interface for packet capture
    async fn validate_capture_interface(&self, interface_name: &str) -> crate::Result<InterfaceValidation>;
}

/// Port for system information
pub trait SystemInfo {
    /// Get operating system information
    fn get_os_info(&self) -> OsInfo;

    /// Check if running with sufficient privileges (for packet capture)
    fn has_capture_privileges(&self) -> bool;

    /// Get current user information
    fn get_current_user(&self) -> crate::Result<UserInfo>;

    /// Get system resource usage
    fn get_system_resources(&self) -> crate::Result<SystemResources>;
}

// ============================================================================
// SUPPORTING TYPES
// ============================================================================

/// Options for process execution
#[derive(Debug, Clone, Default)]
pub struct ExecutionOptions {
    pub working_directory: Option<PathBuf>,
    pub environment_vars: HashMap<String, String>,
    pub timeout: Option<std::time::Duration>,
    pub capture_output: bool,
    pub inherit_environment: bool,
    pub stdin_input: Option<String>,
}

/// Handle to a running process
#[derive(Debug, Clone)]
pub struct ProcessHandle {
    pub id: u32,
    pub command: String,
    pub started_at: chrono::DateTime<chrono::Local>,
    pub working_directory: Option<PathBuf>,
}

/// Result of completed process execution
#[derive(Debug)]
pub struct ProcessResult {
    pub handle: ProcessHandle,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub execution_time: std::time::Duration,
}

/// Information about system tool
#[derive(Debug, Clone)]
pub struct ToolInfo {
    pub available: bool,
    pub version: Option<String>,
    pub path: Option<PathBuf>,
    pub last_checked: chrono::DateTime<chrono::Local>,
}

/// Network interface information
#[derive(Debug, Clone)]
pub struct NetworkInterface {
    pub name: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub is_up: bool,
    pub is_loopback: bool,
    pub is_point_to_point: bool,
    pub is_broadcast: bool,
    pub is_multicast: bool,
    pub mac_address: Option<String>,
    pub ip_addresses: Vec<String>,
    pub mtu: Option<u32>,
    pub interface_type: InterfaceType,
}

/// Type of network interface
#[derive(Debug, Clone, PartialEq)]
pub enum InterfaceType {
    Ethernet,
    Wireless,
    Loopback,
    Virtual,
    Tunnel,
    Bridge,
    Unknown,
}

/// Interface validation result
#[derive(Debug, Clone)]
pub struct InterfaceValidation {
    pub valid: bool,
    pub issues: Vec<String>,
    pub warnings: Vec<String>,
    pub capabilities: InterfaceCapabilities,
}

/// Interface capture capabilities
#[derive(Debug, Clone)]
pub struct InterfaceCapabilities {
    pub can_capture: bool,
    pub supports_promiscuous: bool,
    pub supports_monitor_mode: bool,
    pub max_packet_size: Option<u32>,
}

/// Operating system information
#[derive(Debug, Clone)]
pub struct OsInfo {
    pub name: String,
    pub version: String,
    pub architecture: String,
    pub kernel_version: Option<String>,
}

/// User information
#[derive(Debug, Clone)]
pub struct UserInfo {
    pub username: String,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub home_directory: Option<PathBuf>,
    pub is_admin: bool,
}

/// System resource information
#[derive(Debug, Clone)]
pub struct SystemResources {
    pub cpu_usage_percent: f64,
    pub memory_total_bytes: u64,
    pub memory_available_bytes: u64,
    pub disk_space_total_bytes: u64,
    pub disk_space_available_bytes: u64,
    pub load_average: Option<[f64; 3]>, // 1, 5, 15 minute averages
}

impl ExecutionOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    pub fn with_working_directory(mut self, dir: PathBuf) -> Self {
        self.working_directory = Some(dir);
        self
    }

    pub fn with_env_var(mut self, key: String, value: String) -> Self {
        self.environment_vars.insert(key, value);
        self
    }

    pub fn capture_output(mut self) -> Self {
        self.capture_output = true;
        self
    }
}

impl ProcessResult {
    pub fn success(&self) -> bool {
        self.exit_code == 0
    }

    pub fn failure(&self) -> bool {
        !self.success()
    }
}

impl InterfaceValidation {
    pub fn valid_for_capture(&self) -> bool {
        self.valid && self.capabilities.can_capture
    }
}