// Application layer - orchestrates domain logic for specific use cases
// This layer contains services that coordinate between domain and infrastructure

pub mod cli;

// Re-export CLI components
pub use cli::*;