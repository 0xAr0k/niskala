// Configuration module for application settings
// This module handles loading and saving application configuration

use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub storage_path: PathBuf,
    pub log_level: String,
    pub enable_colors: bool,
    pub enable_emoji: bool,
    pub default_interface: Option<String>,
    pub auto_encrypt: bool,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            storage_path: dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".niskala_secure"),
            log_level: "info".to_string(),
            enable_colors: true,
            enable_emoji: true,
            default_interface: None,
            auto_encrypt: true,
        }
    }
}

impl AppConfig {
    pub fn load() -> crate::Result<Self> {
        // In a real implementation, this would load from a config file
        Ok(Self::default())
    }
    
    pub fn save(&self) -> crate::Result<()> {
        // In a real implementation, this would save to a config file
        Ok(())
    }
}