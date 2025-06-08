use std::path::PathBuf;
use std::collections::HashMap;
use std::process::Stdio;
use async_trait::async_trait;
use tokio::process::Command as AsyncCommand;
use std::process::Command;

use crate::domain::ports::process::*;

// ============================================================================
// PROCESS EXECUTOR IMPLEMENTATION
// ============================================================================

/// Concrete implementation using tokio process execution
pub struct TokioProcessExecutor;

#[async_trait]
impl ProcessExecutor for TokioProcessExecutor {
    async fn execute_command(
        &self,
        command: &str,
        args: &[String],
        options: &ExecutionOptions,
    ) -> crate::Result<ProcessResult> {
        let handle = self.spawn_process(command, args, options).await?;
        self.wait_for_process(&handle).await
    }

    async fn spawn_process(
        &self,
        command: &str,
        args: &[String],
        options: &ExecutionOptions,
    ) -> crate::Result<ProcessHandle> {
        let mut cmd = AsyncCommand::new(command);
        
        // Set arguments
        cmd.args(args);
        
        // Configure stdio
        if options.capture_output {
            cmd.stdout(Stdio::piped());
            cmd.stderr(Stdio::piped());
        }
        
        // Set working directory
        if let Some(ref dir) = options.working_directory {
            cmd.current_dir(dir);
        }
        
        // Set environment variables
        if options.inherit_environment {
            // Keep current environment and add custom vars
            for (key, value) in &options.environment_vars {
                cmd.env(key, value);
            }
        } else {
            // Clear environment and only use custom vars
            cmd.env_clear();
            for (key, value) in &options.environment_vars {
                cmd.env(key, value);
            }
        }
        
        // Spawn the process
        let child = cmd.spawn()?;
        let process_id = child.id().unwrap_or(0);
        
        let handle = ProcessHandle {
            id: process_id,
            command: command.to_string(),
            started_at: chrono::Local::now(),
            working_directory: options.working_directory.clone(),
        };
        
        Ok(handle)
    }

    async fn kill_process(&self, handle: &ProcessHandle) -> crate::Result<()> {
        #[cfg(unix)]
        {
            Command::new("kill")
                .arg("-TERM")
                .arg(handle.id.to_string())
                .output()?;
        }
        
        #[cfg(windows)]
        {
            Command::new("taskkill")
                .args(["/PID", &handle.id.to_string(), "/F"])
                .output()?;
        }
        
        Ok(())
    }

    async fn is_process_running(&self, handle: &ProcessHandle) -> bool {
        #[cfg(unix)]
        {
            Command::new("kill")
                .arg("-0")
                .arg(handle.id.to_string())
                .output()
                .map(|output| output.status.success())
                .unwrap_or(false)
        }
        
        #[cfg(windows)]
        {
            Command::new("tasklist")
                .args(["/FI", &format!("PID eq {}", handle.id)])
                .output()
                .map(|output| {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    stdout.contains(&handle.id.to_string())
                })
                .unwrap_or(false)
        }
    }

    async fn wait_for_process(&self, handle: &ProcessHandle) -> crate::Result<ProcessResult> {
        // This is a simplified implementation
        // In a real system, you'd track the actual child process
        
        let result = ProcessResult {
            handle: handle.clone(),
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
            execution_time: chrono::Local::now().signed_duration_since(handle.started_at).to_std().unwrap_or_default(),
        };
        
        Ok(result)
    }
}

impl TokioProcessExecutor {
    pub fn new() -> Self {
        Self
    }
}

// ============================================================================
// SYSTEM TOOL CHECKER IMPLEMENTATION
// ============================================================================

/// Concrete implementation for checking system tool availability
pub struct StandardToolChecker;

impl SystemToolChecker for StandardToolChecker {
    fn is_tool_available(&self, tool_name: &str) -> bool {
        Command::new("which")
            .arg(tool_name)
            .output()
            .map(|output| output.status.success())
            .unwrap_or_else(|_| {
                // Fallback for Windows
                Command::new("where")
                    .arg(tool_name)
                    .output()
                    .map(|output| output.status.success())
                    .unwrap_or(false)
            })
    }

    fn get_tool_version(&self, tool_name: &str) -> crate::Result<Option<String>> {
        let output = Command::new(tool_name)
            .arg("--version")
            .output()?;
        
        if output.status.success() {
            let version_output = String::from_utf8_lossy(&output.stdout);
            Ok(Self::parse_version(&version_output))
        } else {
            Ok(None)
        }
    }

    fn get_tool_path(&self, tool_name: &str) -> crate::Result<Option<PathBuf>> {
        let output = Command::new("which")
            .arg(tool_name)
            .output()
            .or_else(|_| {
                // Fallback for Windows
                Command::new("where")
                    .arg(tool_name)
                    .output()
            })?;
        
        if output.status.success() {
            let path_str = String::from_utf8_lossy(&output.stdout);
            let path = PathBuf::from(path_str.trim());
            Ok(Some(path))
        } else {
            Ok(None)
        }
    }

    fn check_tools(&self, tool_names: &[&str]) -> HashMap<String, ToolInfo> {
        let mut results = HashMap::new();
        
        for &tool_name in tool_names {
            let available = self.is_tool_available(tool_name);
            let version = if available {
                self.get_tool_version(tool_name).ok().flatten()
            } else {
                None
            };
            let path = if available {
                self.get_tool_path(tool_name).ok().flatten()
            } else {
                None
            };
            
            results.insert(tool_name.to_string(), ToolInfo {
                available,
                version,
                path,
                last_checked: chrono::Local::now(),
            });
        }
        
        results
    }
}

impl StandardToolChecker {
    pub fn new() -> Self {
        Self
    }
    
    fn parse_version(version_output: &str) -> Option<String> {
        // Try to extract version number from various formats
        for line in version_output.lines() {
            if let Some(version) = Self::extract_version_from_line(line) {
                return Some(version);
            }
        }
        None
    }
    
    fn extract_version_from_line(line: &str) -> Option<String> {
        // Look for patterns like "version 1.2.3" or "v1.2.3" or just "1.2.3"
        use regex::Regex;
        
        let patterns = [
            r"version\s+(\d+\.\d+\.\d+)",
            r"v(\d+\.\d+\.\d+)",
            r"(\d+\.\d+\.\d+)",
        ];
        
        for pattern in &patterns {
            if let Ok(re) = Regex::new(pattern) {
                if let Some(captures) = re.captures(line) {
                    if let Some(version) = captures.get(1) {
                        return Some(version.as_str().to_string());
                    }
                }
            }
        }
        
        None
    }
}

// ============================================================================
// NETWORK INTERFACE MANAGER IMPLEMENTATION
// ============================================================================

/// Concrete implementation for network interface management
pub struct SystemNetworkManager;

#[async_trait]
impl NetworkInterfaceManager for SystemNetworkManager {
    async fn list_interfaces(&self) -> crate::Result<Vec<NetworkInterface>> {
        #[cfg(unix)]
        {
            self.list_unix_interfaces().await
        }
        
        #[cfg(windows)]
        {
            self.list_windows_interfaces().await
        }
    }

    async fn interface_exists(&self, interface_name: &str) -> bool {
        if interface_name == "any" {
            return true;
        }
        
        self.list_interfaces()
            .await
            .map(|interfaces| {
                interfaces.iter().any(|iface| iface.name == interface_name)
            })
            .unwrap_or(false)
    }

    async fn get_interface_info(&self, interface_name: &str) -> crate::Result<NetworkInterface> {
        let interfaces = self.list_interfaces().await?;
        
        interfaces
            .into_iter()
            .find(|iface| iface.name == interface_name)
            .ok_or_else(|| format!("Interface '{}' not found", interface_name).into())
    }

    async fn is_interface_active(&self, interface_name: &str) -> crate::Result<bool> {
        let interface = self.get_interface_info(interface_name).await?;
        Ok(interface.is_up)
    }

    async fn validate_capture_interface(&self, interface_name: &str) -> crate::Result<InterfaceValidation> {
        if interface_name == "any" {
            return Ok(InterfaceValidation {
                valid: true,
                issues: Vec::new(),
                warnings: vec!["Using 'any' interface captures all traffic".to_string()],
                capabilities: InterfaceCapabilities {
                    can_capture: true,
                    supports_promiscuous: true,
                    supports_monitor_mode: false,
                    max_packet_size: Some(65535),
                },
            });
        }
        
        let mut issues = Vec::new();
        let mut warnings = Vec::new();
        
        // Check if interface exists
        if !self.interface_exists(interface_name).await {
            issues.push(format!("Interface '{}' does not exist", interface_name));
            return Ok(InterfaceValidation {
                valid: false,
                issues,
                warnings,
                capabilities: InterfaceCapabilities {
                    can_capture: false,
                    supports_promiscuous: false,
                    supports_monitor_mode: false,
                    max_packet_size: None,
                },
            });
        }
        
        // Get interface info
        let interface = self.get_interface_info(interface_name).await?;
        
        // Check if interface is up
        if !interface.is_up {
            warnings.push(format!("Interface '{}' is currently down", interface_name));
        }
        
        // Check interface type
        let capabilities = match interface.interface_type {
            InterfaceType::Loopback => {
                warnings.push("Loopback interface - only captures local traffic".to_string());
                InterfaceCapabilities {
                    can_capture: true,
                    supports_promiscuous: false,
                    supports_monitor_mode: false,
                    max_packet_size: Some(65535),
                }
            },
            InterfaceType::Ethernet | InterfaceType::Wireless => {
                InterfaceCapabilities {
                    can_capture: true,
                    supports_promiscuous: true,
                    supports_monitor_mode: interface.interface_type == InterfaceType::Wireless,
                    max_packet_size: interface.mtu,
                }
            },
            InterfaceType::Virtual | InterfaceType::Tunnel => {
                InterfaceCapabilities {
                    can_capture: true,
                    supports_promiscuous: false,
                    supports_monitor_mode: false,
                    max_packet_size: interface.mtu,
                }
            },
            _ => {
                warnings.push("Unknown interface type - capture may not work properly".to_string());
                InterfaceCapabilities {
                    can_capture: true,
                    supports_promiscuous: false,
                    supports_monitor_mode: false,
                    max_packet_size: None,
                }
            },
        };
        
        Ok(InterfaceValidation {
            valid: issues.is_empty(),
            issues,
            warnings,
            capabilities,
        })
    }
}

impl SystemNetworkManager {
    pub fn new() -> Self {
        Self
    }
    
    #[cfg(unix)]
    async fn list_unix_interfaces(&self) -> crate::Result<Vec<NetworkInterface>> {
        // Use `ip link show` command to list interfaces
        let output = Command::new("ip")
            .args(["link", "show"])
            .output()?;
        
        if !output.status.success() {
            return Err("Failed to list network interfaces".into());
        }
        
        let output_str = String::from_utf8_lossy(&output.stdout);
        let interfaces = self.parse_ip_link_output(&output_str);
        Ok(interfaces)
    }
    
    #[cfg(windows)]
    async fn list_windows_interfaces(&self) -> crate::Result<Vec<NetworkInterface>> {
        // Use netsh command to list interfaces
        let output = Command::new("netsh")
            .args(["interface", "show", "interface"])
            .output()?;
        
        if !output.status.success() {
            return Err("Failed to list network interfaces".into());
        }
        
        let output_str = String::from_utf8_lossy(&output.stdout);
        let interfaces = self.parse_netsh_output(&output_str);
        Ok(interfaces)
    }
    
    fn parse_ip_link_output(&self, output: &str) -> Vec<NetworkInterface> {
        let mut interfaces = Vec::new();
        
        for line in output.lines() {
            if let Some(interface) = self.parse_ip_link_line(line) {
                interfaces.push(interface);
            }
        }
        
        interfaces
    }
    
    fn parse_ip_link_line(&self, line: &str) -> Option<NetworkInterface> {
        // Parse lines like: "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500"
        if !line.contains(":") {
            return None;
        }
        
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            return None;
        }
        
        let name = parts[1].trim_end_matches(':');
        let flags = if parts.len() > 2 { parts[2] } else { "" };
        
        Some(NetworkInterface {
            name: name.to_string(),
            display_name: None,
            description: None,
            is_up: flags.contains("UP"),
            is_loopback: name == "lo",
            is_point_to_point: flags.contains("POINTOPOINT"),
            is_broadcast: flags.contains("BROADCAST"),
            is_multicast: flags.contains("MULTICAST"),
            mac_address: None, // Would need additional parsing
            ip_addresses: Vec::new(), // Would need additional commands
            mtu: None, // Would need additional parsing
            interface_type: Self::determine_interface_type(name),
        })
    }
    
    fn parse_netsh_output(&self, _output: &str) -> Vec<NetworkInterface> {
        // Simplified Windows implementation
        Vec::new()
    }
    
    fn determine_interface_type(name: &str) -> InterfaceType {
        if name == "lo" || name.starts_with("loopback") {
            InterfaceType::Loopback
        } else if name.starts_with("eth") || name.starts_with("en") {
            InterfaceType::Ethernet
        } else if name.starts_with("wlan") || name.starts_with("wifi") || name.starts_with("wl") {
            InterfaceType::Wireless
        } else if name.starts_with("tun") || name.starts_with("tap") {
            InterfaceType::Tunnel
        } else if name.starts_with("br") {
            InterfaceType::Bridge
        } else if name.starts_with("veth") || name.starts_with("docker") {
            InterfaceType::Virtual
        } else {
            InterfaceType::Unknown
        }
    }
}

// ============================================================================
// SYSTEM INFO IMPLEMENTATION
// ============================================================================

/// Concrete implementation for system information
pub struct StandardSystemInfo;

impl SystemInfo for StandardSystemInfo {
    fn get_os_info(&self) -> OsInfo {
        OsInfo {
            name: std::env::consts::OS.to_string(),
            version: "unknown".to_string(), // Would need platform-specific code
            architecture: std::env::consts::ARCH.to_string(),
            kernel_version: None,
        }
    }

    fn has_capture_privileges(&self) -> bool {
        #[cfg(unix)]
        {
            // Check if running as root or has CAP_NET_RAW capability
            unsafe { libc::geteuid() == 0 }
        }
        
        #[cfg(windows)]
        {
            // Check if running as administrator
            // This is a simplified check
            true // Assume true for now
        }
    }

    fn get_current_user(&self) -> crate::Result<UserInfo> {
        Ok(UserInfo {
            username: std::env::var("USER")
                .or_else(|_| std::env::var("USERNAME"))
                .unwrap_or_else(|_| "unknown".to_string()),
            uid: None, // Would need platform-specific code
            gid: None,
            home_directory: dirs::home_dir(),
            is_admin: self.has_capture_privileges(),
        })
    }

    fn get_system_resources(&self) -> crate::Result<SystemResources> {
        // This would typically use a crate like `sysinfo`
        // For now, return dummy values
        Ok(SystemResources {
            cpu_usage_percent: 0.0,
            memory_total_bytes: 0,
            memory_available_bytes: 0,
            disk_space_total_bytes: 0,
            disk_space_available_bytes: 0,
            load_average: None,
        })
    }
}

// ============================================================================
// DEFAULT IMPLEMENTATIONS
// ============================================================================

impl Default for TokioProcessExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for StandardToolChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for SystemNetworkManager {
    fn default() -> Self {
        Self::new()
    }
}
