use clap::Parser;
use std::path::PathBuf;

// CLI argument structure
#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    #[arg(short, long, default_value = "any")]
    pub interface: String,

    #[arg(short, long)]
    pub tshark: bool,

    #[arg(short, long)]
    pub filter: Option<String>,

    #[arg(short = 'c', long)]
    pub count: Option<u32>,

    /// Show detailed packet analysis (like Wireshark's packet details)
    #[arg(short, long)]
    pub verbose: bool,

    /// Show binary/hex dump of packets
    #[arg(short = 'x', long)]
    pub hex: bool,

    /// Show protocol tree breakdown
    #[arg(short = 'P', long)]
    pub tree: bool,

    /// Show only specific fields (e.g., "ip.src,tcp.port")
    #[arg(short = 'T', long)]
    pub fields: Option<String>,

    /// List all encrypted capture files
    #[arg(short, long)]
    pub list: bool,

    /// Decrypt and open a specific capture file (provide filename)
    #[arg(short, long)]
    pub open: Option<String>,
}

impl Args {
    // Convert CLI args to domain capture options
    pub fn to_capture_options(&self) -> crate::domain::entities::CaptureOptions {
        crate::domain::entities::CaptureOptions {
            verbose: self.verbose,
            hex_dump: self.hex,
            protocol_tree: self.tree,
            custom_fields: self.fields.clone(),
        }
    }
}