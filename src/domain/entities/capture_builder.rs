use std::path::PathBuf;
use super::{CaptureSession, CaptureOptions, LiveCaptureSession, FileCaptureSession, Capturable};

// Builder pattern - allows flexible construction
#[derive(Debug, Default)]
pub struct CaptureSessionBuilder {
    interface: Option<String>,
    output_path: Option<PathBuf>,
    filter: Option<String>,
    packet_count: Option<u32>,
    options: CaptureOptions,
}

impl CaptureSessionBuilder {
    pub fn new() -> Self {
        Self::default()
    }
    
    // Chainable methods
    pub fn interface(mut self, interface: impl Into<String>) -> Self {
        self.interface = Some(interface.into());
        self
    }
    
    pub fn output_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.output_path = Some(path.into());
        self
    }
    
    pub fn filter(mut self, filter: impl Into<String>) -> Self {
        self.filter = Some(filter.into());
        self
    }
    
    pub fn packet_count(mut self, count: u32) -> Self {
        self.packet_count = Some(count);
        self
    }
    
    pub fn verbose(mut self) -> Self {
        self.options.verbose = true;
        self
    }
    
    pub fn hex_dump(mut self) -> Self {
        self.options.hex_dump = true;
        self
    }
    
    // Build methods for different types
    pub fn build_live(self) -> crate::Result<LiveCaptureSession> {
        let interface = self.interface.ok_or("Interface is required")?;
        let output_path = self.output_path.ok_or("Output path is required")?;
        
        // Type-specific validation for live captures
        if interface.starts_with("file:") {
            return Err("Live captures cannot use file interfaces".into());
        }
        
        let base = CaptureSession::new(
            interface,
            output_path,
            self.filter,
            self.packet_count,
            self.options,
        )?;
        
        Ok(LiveCaptureSession {
            base,
            interface_validated: false,
        })
    }
    
    pub fn build_file(self) -> crate::Result<FileCaptureSession> {
        let interface = self.interface.ok_or("Interface is required")?;
        let output_path = self.output_path.ok_or("Output path is required")?;
        
        // Type-specific validation for file captures
        if !interface.starts_with("file:") {
            return Err("File captures must specify file: interface".into());
        }
        
        let input_file = PathBuf::from(interface.trim_start_matches("file:"));
        if !input_file.exists() {
            return Err("Input file does not exist".into());
        }
        
        let base = CaptureSession::new(
            interface,
            output_path,
            self.filter,
            self.packet_count,
            self.options,
        )?;
        
        Ok(FileCaptureSession { base, input_file })
    }
    
    // Auto-detect and build appropriate type
    pub fn build(self) -> crate::Result<Box<dyn Capturable>> {
        let interface = self.interface.as_ref().ok_or("Interface is required")?;
        
        if interface.starts_with("file:") {
            Ok(Box::new(self.build_file()?))
        } else {
            Ok(Box::new(self.build_live()?))
        }
    }
}

// Usage examples in tests
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_builder_pattern() -> crate::Result<()> {
        // Fluent interface - much cleaner!
        let session = CaptureSessionBuilder::new()
            .interface("eth0")
            .output_path("/tmp/capture.pcapng")
            .filter("tcp port 80")
            .packet_count(1000)
            .verbose()
            .hex_dump()
            .build_live()?;
            
        assert_eq!(session.base.interface, "eth0");
        assert!(session.base.options.verbose);
        Ok(())
    }
    
    #[test]
    fn test_auto_detection() -> crate::Result<()> {
        // Automatically chooses the right type
        let live_session = CaptureSessionBuilder::new()
            .interface("wlan0")
            .output_path("/tmp/live.pcapng")
            .build()?;
            
        // Returns Box<dyn Capturable> - we don't need to know the concrete type
        live_session.validate()?;
        Ok(())
    }
}