// Infrastructure layer - concrete implementations of domain ports
// This layer contains adapters that connect domain logic to external systems

// Core adapters organized by technology/responsibility
pub mod capture;        // tshark/wireshark implementations
pub mod crypto;         // AES-GCM, Argon2 implementations  
pub mod file_system;    // Standard library file operations
pub mod process;        // System process execution
pub mod validation;     // Concrete validation implementations
pub mod storage;        // File-based storage implementations
pub mod notification;   // Console/terminal user interaction
pub mod websocket;      // WebSocket streaming for real-time data

// Factories for creating adapter instances
pub mod factories;

// Re-export commonly used adapters
pub use capture::*;
pub use crypto::*;
pub use file_system::*;
pub use process::*;
pub use validation::*;
pub use storage::*;
pub use notification::*;
pub use websocket::*;
pub use factories::*;