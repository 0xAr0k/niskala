use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio_tungstenite::{accept_async, tungstenite::Message};
use futures::prelude::*;
use serde::{Deserialize, Serialize};

/// WebSocket streaming server for real-time packet data
pub struct WebSocketStreamer {
    address: SocketAddr,
    sender: broadcast::Sender<PacketData>,
}

/// Packet data structure for streaming
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketData {
    pub timestamp: String,
    pub source: String,
    pub destination: String,
    pub protocol: String,
    pub length: u32,
    pub info: String,
    pub raw_data: Option<String>,
}

impl WebSocketStreamer {
    /// Create a new WebSocket streamer
    pub fn new(address: SocketAddr) -> Self {
        let (sender, _) = broadcast::channel(1024);
        Self { address, sender }
    }

    /// Start the WebSocket server
    pub async fn start(&self) -> crate::Result<()> {
        let listener = tokio::net::TcpListener::bind(self.address).await?;
        println!("🌐 WebSocket server listening on {}", self.address);

        let sender = self.sender.clone();
        
        tokio::spawn(async move {
            while let Ok((stream, addr)) = listener.accept().await {
                println!("🔗 New WebSocket connection from {}", addr);
                let sender_clone = sender.clone();
                
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, sender_clone).await {
                        eprintln!("❌ WebSocket connection error: {}", e);
                    }
                });
            }
        });

        Ok(())
    }

    /// Send packet data to all connected clients
    pub fn send_packet(&self, packet: PacketData) -> crate::Result<()> {
        if self.sender.receiver_count() > 0 {
            let _ = self.sender.send(packet);
        }
        Ok(())
    }

    /// Get a receiver for packet data
    pub fn subscribe(&self) -> broadcast::Receiver<PacketData> {
        self.sender.subscribe()
    }
}

async fn handle_connection(
    stream: tokio::net::TcpStream,
    sender: broadcast::Sender<PacketData>,
) -> crate::Result<()> {
    let ws_stream = accept_async(stream).await?;
    let (ws_sender, mut ws_receiver) = ws_stream.split();
    
    let mut receiver = sender.subscribe();
    
    // Handle incoming WebSocket messages (for configuration, etc.)
    let ws_sender = Arc::new(tokio::sync::Mutex::new(ws_sender));
    let ws_sender_clone = ws_sender.clone();
    
    // Task to send packet data to WebSocket client
    let send_task = tokio::spawn(async move {
        while let Ok(packet) = receiver.recv().await {
            let json = match serde_json::to_string(&packet) {
                Ok(json) => json,
                Err(e) => {
                    eprintln!("❌ Failed to serialize packet: {}", e);
                    continue;
                }
            };
            
            let mut sender = ws_sender_clone.lock().await;
            if let Err(e) = sender.send(Message::Text(json)).await {
                eprintln!("❌ Failed to send WebSocket message: {}", e);
                break;
            }
        }
    });
    
    // Task to handle incoming WebSocket messages
    let receive_task = tokio::spawn(async move {
        while let Some(msg) = ws_receiver.next().await {
            match msg {
                Ok(Message::Text(text)) => {
                    // Handle client messages (could be for filtering, configuration, etc.)
                    println!("📨 Received WebSocket message: {}", text);
                }
                Ok(Message::Close(_)) => {
                    println!("🔚 WebSocket connection closed by client");
                    break;
                }
                Err(e) => {
                    eprintln!("❌ WebSocket message error: {}", e);
                    break;
                }
                _ => {}
            }
        }
    });
    
    // Wait for either task to complete
    tokio::select! {
        _ = send_task => {},
        _ = receive_task => {},
    }
    
    println!("🔌 WebSocket connection closed");
    Ok(())
}

/// Real-time packet formatter for terminal output
pub struct TerminalFormatter {
    format: String,
}

impl TerminalFormatter {
    pub fn new(format: &str) -> Self {
        Self {
            format: format.to_string(),
        }
    }

    /// Format packet data for terminal display
    pub fn format_packet(&self, packet: &PacketData) -> String {
        match self.format.as_str() {
            "json" => serde_json::to_string_pretty(packet).unwrap_or_default(),
            "compact" => format!(
                "{} {} -> {} [{}] {} bytes: {}",
                packet.timestamp,
                packet.source,
                packet.destination,
                packet.protocol,
                packet.length,
                packet.info
            ),
            "text" | _ => format!(
                "🕒 {} | 📡 {} → {} | 📋 {} | 📊 {} bytes | ℹ️  {}",
                packet.timestamp,
                packet.source,
                packet.destination,
                packet.protocol,
                packet.length,
                packet.info
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_serialization() {
        let packet = PacketData {
            timestamp: "2023-01-01 12:00:00".to_string(),
            source: "192.168.1.1".to_string(),
            destination: "192.168.1.2".to_string(),
            protocol: "TCP".to_string(),
            length: 1024,
            info: "Test packet".to_string(),
            raw_data: None,
        };

        let json = serde_json::to_string(&packet).unwrap();
        assert!(json.contains("192.168.1.1"));
    }

    #[test]
    fn test_terminal_formatter() {
        let packet = PacketData {
            timestamp: "12:00:00".to_string(),
            source: "192.168.1.1".to_string(),
            destination: "192.168.1.2".to_string(),
            protocol: "TCP".to_string(),
            length: 1024,
            info: "Test".to_string(),
            raw_data: None,
        };

        let formatter = TerminalFormatter::new("compact");
        let output = formatter.format_packet(&packet);
        assert!(output.contains("192.168.1.1"));
        assert!(output.contains("TCP"));
    }
}