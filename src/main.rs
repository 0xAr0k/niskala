use clap::Parser;
use std::path::PathBuf;

// Import our library components
use secure_wireshark::{
    application::cli::Args,
    infrastructure::factories::{create_default_container, DependencyContainer},
    domain::entities::CaptureSession,
    domain::ports::notification::UserNotification,
    domain::ports::validation::{CaptureConfig, ValidationSeverity, CaptureConfigValidator},
    Result,
};

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let args = Args::parse();
    
    // Create dependency container with default configuration
    let mut container = create_default_container();
    
    // Handle different commands
    match determine_command(&args) {
        Command::ListFiles => {
            handle_list_command(&mut container).await?;
        }
        Command::OpenFile(filename) => {
            handle_open_command(&mut container, &filename).await?;
        }
        Command::StartCapture => {
            handle_capture_command(&mut container, &args).await?;
        }
    }
    
    Ok(())
}

// Enum to represent different commands
#[derive(Debug)]
enum Command {
    ListFiles,
    OpenFile(String),
    StartCapture,
}

// Determine which command to execute based on args
fn determine_command(args: &Args) -> Command {
    if args.list {
        Command::ListFiles
    } else if let Some(ref filename) = args.open {
        Command::OpenFile(filename.clone())
    } else {
        Command::StartCapture
    }
}

// Handle listing encrypted files
async fn handle_list_command(container: &mut DependencyContainer) -> Result<()> {
    let notifier = container.user_notification();
    let repository = container.encrypted_capture_repository();
    
    notifier.show_info("📋 Listing encrypted capture files...").await?;
    
    let captures = repository.list_captures().await?;
    
    if captures.is_empty() {
        notifier.show_info("📭 No encrypted files found").await?;
        notifier.show_info("💡 Create captures with: cargo run -- --tshark").await?;
    } else {
        notifier.show_info(&format!("Found {} encrypted capture(s):", captures.len())).await?;
        println!("{}", "=".repeat(60));
        
        for capture in captures {
            let size_mb = capture.storage_info.encrypted_size as f64 / (1024.0 * 1024.0);
            println!(
                "📦 {} ({:.1} MB) - {} - Interface: {}", 
                capture.storage_info.handle.id,
                size_mb,
                capture.session_info.captured_at.format("%Y-%m-%d %H:%M:%S"),
                capture.session_info.interface
            );
        }
    }
    
    Ok(())
}

// Handle opening/decrypting a file
async fn handle_open_command(
    container: &mut DependencyContainer, 
    filename: &str
) -> Result<()> {
    let notifier = container.user_notification();
    let repository = container.encrypted_capture_repository();
    
    notifier.show_info(&format!("🔓 Opening encrypted file: {}", filename)).await?;
    
    // Find the file by ID (simplified - in reality you'd have better file selection)
    let captures = repository.list_captures().await?;
    let target_capture = captures
        .into_iter()
        .find(|c| c.storage_info.handle.id.contains(filename))
        .ok_or_else(|| format!("File '{}' not found", filename))?;
    
    // Get password from user
    let password = notifier.ask_password("Enter password to decrypt file").await?;
    
    // Decrypt the file
    let progress = container.progress_reporter();
    let progress_handle = progress.start_progress("Decrypting file", None).await?;
    
    let decrypted_path = repository
        .retrieve_capture(&target_capture.storage_info.handle, &password, None)
        .await?;
    
    progress.complete_progress(&progress_handle, Some("File decrypted")).await?;
    
    // Ask if user wants to open in Wireshark
    let should_open = notifier
        .ask_confirmation("Open decrypted file in Wireshark?")
        .await?;
    
    if should_open {
        notifier.show_info("🖥️  Launching Wireshark...").await?;
        
        // Use std::process to launch Wireshark
        let output = std::process::Command::new("wireshark")
            .arg(&decrypted_path)
            .spawn()
            .map_err(|e| format!("Failed to launch Wireshark: {}", e))?
            .wait()
            .map_err(|e| format!("Wireshark process error: {}", e))?;
        
        if output.success() {
            notifier.show_success("Wireshark launched successfully").await?;
        } else {
            notifier.show_warning("Wireshark exited with errors").await?;
        }
        
        // Clean up decrypted file
        notifier.show_info("🗑️  Cleaning up temporary decrypted file...").await?;
        std::fs::remove_file(&decrypted_path)?;
        notifier.show_success("Cleanup completed").await?;
    } else {
        notifier.show_info(&format!("Decrypted file available at: {}", decrypted_path.display())).await?;
        notifier.show_warning("Remember to delete the decrypted file when done!").await?;
    }
    
    Ok(())
}

// Handle starting a new capture
async fn handle_capture_command(
    container: &mut DependencyContainer,
    args: &Args,
) -> Result<()> {
    let notifier = container.user_notification();
    let capture_executor = container.capture_executor();
    let repository = container.encrypted_capture_repository();
    let validator = container.create_capture_config_validator();
    
    // Show warning about GUI vs tshark
    if !args.tshark {
        notifier.show_warning("⚠️  WARNING: Wireshark GUI mode does not support automatic encryption!").await?;
        notifier.show_info("💡 Use --tshark flag for encrypted capture, or manually encrypt files later.").await?;
        
        let continue_gui = notifier
            .ask_confirmation("Continue with GUI mode?")
            .await?;
        
        if !continue_gui {
            notifier.show_info("❌ Cancelled. Use: cargo run -- --tshark for encrypted capture").await?;
            return Ok(());
        }
        
        // Launch Wireshark GUI (simplified)
        return launch_wireshark_gui(args, &notifier).await;
    }
    
    // Validate configuration
    let config = CaptureConfig {
        interface: args.interface.clone(),
        filter: args.filter.clone(),
        output_path: generate_output_path()?,
        packet_count: args.count,
        timeout: None,
    };
    
    let validation = validator.validate_capture_config(&config).await?;
    
    if !validation.overall_valid {
        notifier.show_error("❌ Configuration validation failed:").await?;
        for result in &validation.results {
            if !result.valid {
                notifier.show_error(&format!("  • {}", result.message)).await?;
            }
        }
        return Err("Invalid capture configuration".into());
    }
    
    // Show warnings if any
    if validation.has_warnings() {
        for result in &validation.results {
            if result.valid && result.severity == ValidationSeverity::Warning {
                notifier.show_warning(&format!("⚠️  {}", result.message)).await?;
            }
        }
    }
    
    // Get password for encryption
    let password = notifier.ask_password("Enter password for encrypting capture").await?;
    
    // Create capture session
    let capture_options = secure_wireshark::domain::entities::CaptureOptions {
        verbose: args.verbose,
        hex_dump: args.hex,
        protocol_tree: args.tree,
        custom_fields: args.fields.clone(),
    };
    let session = CaptureSession::new(
        args.interface.clone(),
        config.output_path.clone(),
        args.filter.clone(),
        args.count,
        capture_options,
    )?;
    
    // Start capture
    notifier.show_info(&format!("🔍 Starting tshark capture on interface: {}", args.interface)).await?;
    
    if let Some(ref filter) = args.filter {
        notifier.show_info(&format!("📡 Filter: {}", filter)).await?;
    }
    
    // Show analysis options
    if session.options.protocol_tree {
        notifier.show_info("🌳 Protocol tree analysis enabled").await?;
    }
    if session.options.hex_dump {
        notifier.show_info("🔢 Hex dump enabled").await?;
    }
    if session.options.verbose {
        notifier.show_info("📋 Verbose packet details enabled").await?;
    }
    
    notifier.show_info("⏹️  Press Ctrl+C to stop").await?;
    
    // Create progress reporter
    let progress = container.progress_reporter();
    let progress_handle = progress.start_progress("Capturing packets", args.count.map(|c| c as u64)).await?;
    
    // Start the capture (simplified - in reality this would be more complex)
    let capture_handle = capture_executor
        .start_live_capture(&args.interface, &config.output_path, &session.options)
        .await?;
    
    // Simulate capture progress (in reality, you'd monitor the actual process)
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    progress.update_progress(&progress_handle, 50, Some("Capturing...")).await?;
    
    // Stop capture (simplified)
    let result = capture_executor.stop_capture(capture_handle).await?;
    progress.complete_progress(&progress_handle, Some(&format!("Captured {} packets", result.packets_captured))).await?;
    
    // Store encrypted capture
    notifier.show_info("🔒 Encrypting and storing capture...").await?;
    let storage_handle = repository
        .store_capture(&session, &result.output_file, &password)
        .await?;
    
    notifier.show_success(&format!("✅ Capture completed and encrypted! Storage ID: {}", storage_handle.id)).await?;
    
    Ok(())
}

// Launch Wireshark GUI (simplified implementation)
async fn launch_wireshark_gui(args: &Args, notifier: &std::sync::Arc<dyn UserNotification + Send + Sync>) -> Result<()> {
    notifier.show_info(&format!("🖥️  Launching Wireshark GUI on interface: {}", args.interface)).await?;
    
    let mut cmd = std::process::Command::new("wireshark");
    cmd.arg("-i").arg(&args.interface).arg("-k");
    
    if let Some(ref filter) = args.filter {
        cmd.arg("-f").arg(filter);
        notifier.show_info(&format!("📡 Filter: {}", filter)).await?;
    }
    
    let output = cmd.spawn()
        .map_err(|e| format!("Failed to launch Wireshark: {}", e))?
        .wait()
        .map_err(|e| format!("Wireshark process error: {}", e))?;
    
    if output.success() {
        notifier.show_success("Wireshark GUI launched").await?;
    } else {
        notifier.show_error("Wireshark exited with errors").await?;
    }
    
    Ok(())
}

// Generate a unique output path for captures
fn generate_output_path() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or("Could not find home directory")?;
    let storage_dir = home.join(".niskala_secure");
    
    if !storage_dir.exists() {
        std::fs::create_dir_all(&storage_dir)?;
    }
    
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    
    Ok(storage_dir.join(format!("capture_{}.pcapng", timestamp)))
}