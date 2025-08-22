// Configuration module for application settings
// This module handles loading and saving application configuration

use std::path::PathBuf;
use std::fs;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
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
        let config_path = Self::get_config_path();
        
        if config_path.exists() {
            let content = fs::read_to_string(&config_path)
                .map_err(|e| format!("Failed to read config file: {}", e))?;
            
            let config: AppConfig = toml::from_str(&content)
                .map_err(|e| format!("Failed to parse config file: {}", e))?;
            
            Ok(config)
        } else {
            // Create default config and save it
            let default_config = Self::default();
            default_config.save()?;
            Ok(default_config)
        }
    }
    
    pub fn save(&self) -> crate::Result<()> {
        let config_path = Self::get_config_path();
        
        // Create parent directory if it doesn't exist
        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create config directory: {}", e))?;
        }
        
        let content = toml::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize config: {}", e))?;
        
        fs::write(&config_path, content)
            .map_err(|e| format!("Failed to write config file: {}", e))?;
        
        Ok(())
    }
    
    fn get_config_path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")))
            .join("niskala")
            .join("config.toml")
    }
    
    pub fn get_config_dir() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")))
            .join("niskala")
    }
    
    pub fn update_storage_path(&mut self, path: PathBuf) {
        self.storage_path = path;
    }
    
    pub fn update_log_level(&mut self, level: String) {
        self.log_level = level;
    }
    
    pub fn update_default_interface(&mut self, interface: Option<String>) {
        self.default_interface = interface;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;
    
    #[test]
    fn test_config_serialization() {
        let config = AppConfig::default();
        let serialized = toml::to_string(&config).unwrap();
        let deserialized: AppConfig = toml::from_str(&serialized).unwrap();
        
        assert_eq!(config.log_level, deserialized.log_level);
        assert_eq!(config.enable_colors, deserialized.enable_colors);
        assert_eq!(config.auto_encrypt, deserialized.auto_encrypt);
    }
    
    #[test]
    fn test_config_load_save() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.toml");
        
        let mut config = AppConfig::default();
        config.log_level = "debug".to_string();
        config.enable_colors = false;
        
        // Mock the config path for testing
        let content = toml::to_string(&config).unwrap();
        fs::write(&config_path, content).unwrap();
        
        // Verify we can read it back
        let content = fs::read_to_string(&config_path).unwrap();
        let loaded_config: AppConfig = toml::from_str(&content).unwrap();
        
        assert_eq!(config.log_level, loaded_config.log_level);
        assert_eq!(config.enable_colors, loaded_config.enable_colors);
    }
}