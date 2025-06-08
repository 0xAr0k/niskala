use std::path::PathBuf;
use chrono::{DateTime, Local};

// ============================================================================
// STRUCTS: Concrete data types (what something IS)
// ============================================================================

#[derive(Debug, Clone)]
pub struct CaptureSession {
    pub interface: String,
    pub output_path: PathBuf,
    pub filter: Option<String>,
    pub packet_count: Option<u32>,
    pub options: CaptureOptions,
    pub created_at: DateTime<Local>,
}

#[derive(Debug, Clone, Default)]
pub struct CaptureOptions {
    pub verbose: bool,
    pub hex_dump: bool,
    pub protocol_tree: bool,
    pub custom_fields: Option<String>,
}

// Different types of capture sessions
#[derive(Debug, Clone)]
pub struct LiveCaptureSession {
    pub base: CaptureSession,
    pub interface_validated: bool,
}

#[derive(Debug, Clone)]
pub struct FileCaptureSession {
    pub base: CaptureSession,
    pub input_file: PathBuf,
}

// ============================================================================
// TRAITS: Behavior contracts (what something CAN DO)
// ============================================================================

// This trait defines what ALL capture sessions can do
pub trait Capturable {
    // Required methods that implementers must provide
    fn start_capture(&self) -> crate::Result<()>;
    fn stop_capture(&self) -> crate::Result<()>;
    fn is_active(&self) -> bool;
    fn get_output_path(&self) -> &PathBuf;
    
    // Default implementations (can be overridden)
    fn validate(&self) -> crate::Result<()> {
        Ok(()) // Default: no validation needed
    }
    
    fn estimated_duration(&self) -> Option<std::time::Duration> {
        None // Default: unknown duration
    }
}

// Another trait for sessions that can be configured
pub trait Configurable {
    fn apply_filter(&mut self, filter: String);
    fn set_packet_count(&mut self, count: u32);
    fn enable_verbose(&mut self);
}

// ============================================================================
// IMPLEMENTATIONS: How concrete types fulfill the contracts
// ============================================================================

impl CaptureSession {
    pub fn new(
        interface: String,
        output_path: PathBuf,
        filter: Option<String>,
        packet_count: Option<u32>,
        options: CaptureOptions,
    ) -> crate::Result<Self> {
        // Validation logic
        if interface.trim().is_empty() {
            return Err("Interface cannot be empty".into());
        }

        if let Some(count) = packet_count {
            if count == 0 {
                return Err("Packet count must be greater than 0".into());
            }
        }

        Ok(Self {
            interface,
            output_path,
            filter,
            packet_count,
            options,
            created_at: Local::now(),
        })
    }

    // Business logic methods
    pub fn is_live_capture(&self) -> bool {
        self.interface == "any" || !self.interface.contains("file:")
    }

    pub fn generate_filename(&self) -> String {
        let timestamp = self.created_at.timestamp();
        format!("capture_{}.pcapng", timestamp)
    }
}

// Implement the Capturable trait for LiveCaptureSession
impl Capturable for LiveCaptureSession {
    fn start_capture(&self) -> crate::Result<()> {
        if !self.interface_validated {
            return Err("Interface not validated".into());
        }
        // Implementation would delegate to infrastructure layer
        println!("Starting live capture on {}", self.base.interface);
        Ok(())
    }

    fn stop_capture(&self) -> crate::Result<()> {
        println!("Stopping live capture");
        Ok(())
    }

    fn is_active(&self) -> bool {
        // Would check actual capture status
        false
    }

    fn get_output_path(&self) -> &PathBuf {
        &self.base.output_path
    }

    fn validate(&self) -> crate::Result<()> {
        if self.base.interface == "any" {
            return Ok(());
        }
        // Would delegate to infrastructure to check if interface exists
        Ok(())
    }
}

// Implement the Capturable trait for FileCaptureSession  
impl Capturable for FileCaptureSession {
    fn start_capture(&self) -> crate::Result<()> {
        if !self.input_file.exists() {
            return Err("Input file does not exist".into());
        }
        println!("Starting file-based capture from {:?}", self.input_file);
        Ok(())
    }

    fn stop_capture(&self) -> crate::Result<()> {
        println!("File capture completed");
        Ok(())
    }

    fn is_active(&self) -> bool {
        // File captures are typically not "active" in the same way
        false
    }

    fn get_output_path(&self) -> &PathBuf {
        &self.base.output_path
    }

    fn estimated_duration(&self) -> Option<std::time::Duration> {
        // Could estimate based on file size
        Some(std::time::Duration::from_secs(30))
    }
}

// Implement Configurable for both types
impl Configurable for LiveCaptureSession {
    fn apply_filter(&mut self, filter: String) {
        self.base.filter = Some(filter);
    }

    fn set_packet_count(&mut self, count: u32) {
        self.base.packet_count = Some(count);
    }

    fn enable_verbose(&mut self) {
        self.base.options.verbose = true;
    }
}

impl Configurable for FileCaptureSession {
    fn apply_filter(&mut self, filter: String) {
        self.base.filter = Some(filter);
    }

    fn set_packet_count(&mut self, count: u32) {
        self.base.packet_count = Some(count);
    }

    fn enable_verbose(&mut self) {
        self.base.options.verbose = true;
    }
}

// ============================================================================
// FACTORY PATTERN: Create the right type based on input
// ============================================================================

pub fn create_capture_session(
    interface: String,
    output_path: PathBuf,
    filter: Option<String>,
    packet_count: Option<u32>,
    options: CaptureOptions,
) -> crate::Result<Box<dyn Capturable>> {
    let base = CaptureSession::new(interface.clone(), output_path, filter, packet_count, options)?;
    
    if interface.starts_with("file:") {
        let input_file = PathBuf::from(interface.trim_start_matches("file:"));
        Ok(Box::new(FileCaptureSession { base, input_file }))
    } else {
        Ok(Box::new(LiveCaptureSession { 
            base, 
            interface_validated: false 
        }))
    }
}