pub mod domain;
pub mod infrastructure;
pub mod application;
pub mod config;

pub use application::cli::Args;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

pub const SALT_SIZE: usize = 16;
pub const NONCE_SIZE: usize = 12;
pub const KEY_SIZE: usize = 32;
pub const HEADER_SIZE: usize = SALT_SIZE + NONCE_SIZE;


