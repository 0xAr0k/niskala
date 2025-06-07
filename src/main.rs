use clap::Parser;
use std::process::{Command, Stdio};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command as AsyncCommand;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]

struct Args {
    #[arg(short, long, default_value = "any")]
    interface: String,

    #[arg(short, long)]
    tshark: bool,

    #[arg(short, long)]
    filter: Option<String>,

    #[arg(short = 'c', long)]
    count: Option<u32>,

    /// Show detailed packet analysis (like Wireshark's packet details)
    #[arg(short, long)]
    verbose: bool,

    /// Show binary/hex dump of packets
    #[arg(short = 'x', long)]
    hex: bool,

    /// Show protocol tree breakdown
    #[arg(short = 'P', long)]
    tree: bool,

    /// Show only specific fields (e.g., "ip.src,tcp.port")
    #[arg(short = 'T', long)]
    fields: Option<String>,
}

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;


fn check_tool_availability(tool: &str) -> Result<bool> {
    Command::new("which")
        .arg(tool)
        .output()
        .map(|output| output.status.success())
        .map_err(Into::into)
}

fn build_tshark_command(args: &Args) -> Vec<String> {
    let mut cmd_args = vec![
        "-i".to_string(),
        args.interface.clone(),
        "-l".to_string(), 
    ];

    // Basic packet count
    if let Some(count) = args.count {
        cmd_args.extend(["-c".to_string(), count.to_string()]);
    }

    // Capture filter
    if let Some(ref filter) = args.filter {
        cmd_args.extend(["-f".to_string(), filter.clone()]);
    }

    // DETAILED ANALYSIS OPTIONS
    
    // Show protocol tree breakdown (-V)
    if args.tree {
        cmd_args.push("-V".to_string());
    }
    
    // Show hex dump (-x)
    if args.hex {
        cmd_args.push("-x".to_string());
    }
    
    // Verbose output (-v) - shows detailed packet info
    if args.verbose {
        cmd_args.push("-v".to_string());
    }
    
    // Custom fields output (-T fields -e field1 -e field2)
    if let Some(ref fields) = args.fields {
        cmd_args.extend(["-T".to_string(), "fields".to_string()]);
        for field in fields.split(',') {
            cmd_args.extend(["-e".to_string(), field.trim().to_string()]);
        }
        // Add headers for readability
        cmd_args.push("-E".to_string());
        cmd_args.push("header=y".to_string());
    }

    cmd_args
}

fn build_wireshark_command(args: &Args) -> Vec<String> {
    let mut cmd_args = vec![
        "-i".to_string(),
        args.interface.clone(),
        "-k".to_string(), 
    ];

    if let Some(ref filter) = args.filter {
        cmd_args.extend(["-f".to_string(), filter.clone()]);
    }

    cmd_args
}

async fn run_tshark_monitor(args: &Args) -> Result<()> {
    let cmd_args = build_tshark_command(args);
    
    println!("🔍 Starting tshark traffic monitoring on interface: {}", args.interface);
    if let Some(ref filter) = args.filter {
        println!("📡 Filter: {}", filter);
    }
    
    // Show analysis mode
    if args.tree {
        println!("🌳 Protocol tree analysis enabled");
    }
    if args.hex {
        println!("🔢 Hex dump enabled");
    }
    if args.verbose {
        println!("📋 Verbose packet details enabled");
    }
    if let Some(ref fields) = args.fields {
        println!("🎯 Custom fields: {}", fields);
    }
    
    println!("⏹️  Press Ctrl+C to stop\n");

    let mut child = AsyncCommand::new("tshark")
        .args(&cmd_args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    if let Some(stdout) = child.stdout.take() {
        let reader = BufReader::new(stdout);
        let mut lines = reader.lines();

        while let Some(line) = lines.next_line().await? {
            println!("📦 {}", line);
        }
    }

    child.wait().await?;
    Ok(())
}

fn run_wireshark_gui(args: &Args) -> Result<()> {
    let cmd_args = build_wireshark_command(args);
    
    println!("🖥️  Launching Wireshark GUI on interface: {}", args.interface);
    if let Some(ref filter) = args.filter {
        println!("📡 Filter: {}", filter);
    }

    Command::new("wireshark")
        .args(&cmd_args)
        .spawn()?
        .wait()?;

    Ok(())
}

fn validate_interface(interface: &str) -> Result<()> {
    if interface == "any" {
        return Ok(());
    }

    let output = Command::new("ip")
        .args(["link", "show", interface])
        .output()?;

    if !output.status.success() {
        return Err(format!("Interface '{}' not found", interface).into());
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    if let Err(e) = validate_interface(&args.interface) {
        eprintln!("❌ Error: {}", e);
        eprintln!("💡 Use 'ip link show' to list available interfaces");
        return Err(e);
    }

    let (tshark_available, wireshark_available) = (
        check_tool_availability("tshark")?,
        check_tool_availability("wireshark")?
    );

    match (args.tshark, tshark_available, wireshark_available) {
        (true, true, _) => run_tshark_monitor(&args).await,
        (false, _, true) => run_wireshark_gui(&args),
        (false, true, false) => {
            println!("⚠️  Wireshark GUI not available, falling back to tshark");
            run_tshark_monitor(&args).await
        }
        _ => {
            eprintln!("❌ Neither tshark nor wireshark is available");
            eprintln!("💡 Install with: sudo apt install wireshark-qt tshark");
            Err("Required tools not found".into())
        }
    }
}
