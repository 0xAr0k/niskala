pub mod capture;       // Network capture operations
pub mod encryption;    // Encryption/decryption operations  
pub mod file_system;   // File and storage operations
pub mod process;       // System process execution
pub mod validation;    // External validation services

pub mod repository;    // Data persistence abstractions
pub mod notification;  // User notification abstractions

pub use capture::*;
pub use encryption::*;
pub use file_system::*;
pub use process::*;
pub use validation::*;
pub use repository::*;
pub use notification::*;
