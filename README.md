# Niskala - Advanced Wireshark CLI Wrapper

_"Invisible/unseen" - encrypted packet capture tool with real-time streaming_

Niskala is a Javanese word meaning "invisible" or "unseen". This is a powerful, security-focused Wireshark CLI wrapper that provides encrypted packet capture, real-time streaming via WebSocket, and advanced terminal output formatting.

## 🛠️ Installation

### Prerequisites

- **Rust** (1.70+)
- **Wireshark/tshark** installed and in PATH
- **Root/Administrator privileges** for packet capture

```bash
# Ubuntu/Debian
sudo apt install wireshark-qt tshark
sudo setcap cap_net_raw,cap_net_admin=eip $(which tshark)

# macOS
brew install wireshark

# Arch Linux
sudo pacman -S wireshark-qt
sudo setcap cap_net_raw,cap_net_admin=eip $(which tshark)

# Windows
# Download from: https://www.wireshark.org/download.html
```

### From Source

```bash
# Clone the repository
git clone https://github.com/0xAr0k/niskala
cd niskala

# Build optimized release
cargo build --release

# Install globally (optional)
cargo install --path .
```

## 🚀 Features

- **🔐 AES-GCM Encrypted Storage** - All captures are automatically encrypted
- **🌐 Real-time WebSocket Streaming** - Stream packets live to web interfaces
- **📺 Live Terminal Output** - Multiple format options (text, JSON, compact)
- **🎯 Advanced Filtering** - BPF filters with validation
- **📊 Multiple Export Formats** - File, WebSocket, or both simultaneously
- **🛡️ Security-First Design** - Privilege validation and secure file handling
- **🔍 Packet Analysis** - Protocol trees, hex dumps, custom field extraction

## 📖 Command Line Reference

### Core Options
```bash
Usage: niskala [OPTIONS]

Options:
  -i, --interface <INTERFACE>          Network interface [default: any]
  -t, --tshark                         Use tshark for encrypted capture
  -f, --filter <FILTER>                Capture filter (BPF syntax)
  -c, --count <COUNT>                  Max packets to capture
```

### Analysis Options
```bash
  -v, --verbose                        Show detailed packet analysis
  -x, --hex                            Show binary/hex dump of packets
  -P, --tree                           Show protocol tree breakdown
  -T, --fields <FIELDS>                Show specific fields (comma-separated)
```

### Export & Streaming Options
```bash
  -e, --export <EXPORT>                Export format: file, ws, both [default: file]
      --ws-address <WS_ADDRESS>        WebSocket server address [default: 127.0.0.1:8080]
  -r, --realtime                       Real-time output to terminal
      --output-format <OUTPUT_FORMAT>  Terminal format: text, json, compact [default: text]
```

### File Management
```bash
  -l, --list                           List all encrypted capture files
  -o, --open <FILENAME>                Decrypt and open specific file
  -h, --help                           Print help
  -V, --version                        Print version
```

## 🎯 Usage Examples

### Basic Encrypted Capture

```bash
# Basic encrypted capture with real-time output
niskala --tshark --count 50 --realtime

# Capture with WebSocket streaming
niskala --tshark --export ws --ws-address 0.0.0.0:8080

# Both file and WebSocket export
niskala --tshark --export both --realtime --output-format json
```

### Advanced Filtering & Analysis

```bash
# HTTPS traffic analysis with protocol tree
niskala --tshark --filter "tcp port 443" --tree --verbose --count 100

# DNS monitoring with custom fields and real-time JSON output
niskala --tshark --filter "port 53" --fields "dns.qry.name,dns.resp.addr" --realtime --output-format json

# Comprehensive network analysis with hex dumps
niskala --tshark --filter "not port 22" --hex --verbose --count 200 --realtime
```

### Interface-Specific Captures

```bash
# Monitor specific interface with compact real-time display
niskala --interface eth0 --tshark --realtime --output-format compact --count 500

# WiFi interface monitoring with WebSocket streaming
niskala --interface wlan0 --tshark --export ws --filter "not arp" --realtime

# Monitor loopback with detailed analysis
niskala --interface lo --tshark --tree --verbose --hex --count 50
```

### Real-time Output Formats

```bash
# Text format (default) - emoji-rich, human-readable
niskala --tshark --realtime --output-format text

# JSON format - structured data for parsing
niskala --tshark --realtime --output-format json

# Compact format - minimal, dense information
niskala --tshark --realtime --output-format compact
```

### File Management

```bash
# List all encrypted captures
niskala --list

# Open and decrypt specific file in Wireshark
niskala --open a1b2c3d4

# View capture without opening Wireshark
niskala --open a1b2c3d4 --no-wireshark
```

## 🌐 WebSocket Streaming

### Starting a WebSocket Server

```bash
# Start capture with WebSocket streaming
niskala --tshark --export ws --ws-address 0.0.0.0:8080 --filter "tcp"
```

### WebSocket Data Format

The WebSocket server streams JSON packets in real-time:

```json
{
  "timestamp": "14:30:22.123",
  "source": "192.168.1.100",
  "destination": "93.184.216.34",
  "protocol": "TCP",
  "length": 1514,
  "info": "[PSH, ACK] Seq=1 Ack=1 Win=65535 Len=1460",
  "raw_data": null
}
```

### Connecting to WebSocket

```javascript
// JavaScript client example
const ws = new WebSocket('ws://localhost:8080');
ws.onmessage = (event) => {
    const packet = JSON.parse(event.data);
    console.log(`${packet.timestamp}: ${packet.source} → ${packet.destination} [${packet.protocol}]`);
};
```

## 🔐 Security Features

### Encryption
- **AES-GCM encryption** with Argon2 key derivation
- **Password-protected** capture files
- **Secure key handling** with memory protection
- **Automatic cleanup** of temporary decrypted files

### Privilege Management
- **Capability validation** before capture
- **Interface permission checks**
- **Safe file path validation** (prevents directory traversal)
- **Network interface validation**

### Example Security Validation Output
```bash
❌ Configuration validation failed:
  • Insufficient privileges for packet capture
  • Interface 'eth999' does not exist
  • Invalid filter syntax: malformed expression
```

## 🎨 Output Examples

### Text Format (Default)
```
🕒 14:30:22.123 | 📡 192.168.1.100 → 93.184.216.34 | 📋 TCP | 📊 1514 bytes | ℹ️  [PSH, ACK] Seq=1 Ack=1
🕒 14:30:22.124 | 📡 93.184.216.34 → 192.168.1.100 | 📋 TCP | 📊 1460 bytes | ℹ️  [ACK] Seq=1461 Ack=1461
```

### JSON Format
```json
{"timestamp":"14:30:22.123","source":"192.168.1.100","destination":"93.184.216.34","protocol":"TCP","length":1514,"info":"[PSH, ACK] Seq=1 Ack=1"}
```

### Compact Format
```
14:30:22.123 192.168.1.100 -> 93.184.216.34 [TCP] 1514 bytes: [PSH, ACK] Seq=1 Ack=1
14:30:22.124 93.184.216.34 -> 192.168.1.100 [TCP] 1460 bytes: [ACK] Seq=1461 Ack=1461
```

## 🛡️ Defensive Security Use Cases

### Network Monitoring
```bash
# Monitor for suspicious connections
niskala --tshark --filter "tcp[tcpflags] & tcp-syn != 0" --realtime --export ws

# DNS exfiltration detection
niskala --tshark --filter "dns and greater 512" --realtime --output-format json

# Detect port scanning
niskala --tshark --filter "tcp[tcpflags] & tcp-rst != 0" --count 1000 --realtime
```

### Incident Response
```bash
# Capture suspicious traffic with full analysis
niskala --tshark --verbose --hex --tree --export both --realtime

# Monitor specific host communications
niskala --tshark --filter "host 192.168.1.100" --fields "ip.src,ip.dst,tcp.port" --realtime

# Protocol anomaly detection
niskala --tshark --filter "tcp[tcpflags] == 0" --realtime --export ws
```

### Security Analysis
```bash
# Encrypted traffic analysis
niskala --tshark --filter "tcp port 443" --fields "ip.src,ip.dst,tls.handshake.type" --realtime

# Unusual protocol monitoring
niskala --tshark --filter "not tcp and not udp and not icmp" --verbose --realtime

# Connection pattern analysis
niskala --tshark --filter "tcp[tcpflags] & tcp-syn != 0" --fields "ip.src,ip.dst,tcp.dstport" --count 1000
```

## 🚨 Common Use Cases

### 1. Web Traffic Analysis
```bash
# Monitor HTTP/HTTPS with real-time JSON output for analysis tools
niskala --tshark --filter "tcp port 80 or tcp port 443" --fields "ip.src,ip.dst,http.host,http.request.uri" --realtime --output-format json --export ws
```

### 2. DNS Monitoring
```bash
# Real-time DNS query monitoring with WebSocket streaming
niskala --tshark --filter "port 53" --fields "dns.qry.name,dns.qry.type,dns.resp.addr" --realtime --export both
```

### 3. Network Troubleshooting
```bash
# Comprehensive network analysis with all details
niskala --tshark --verbose --tree --hex --count 100 --realtime --output-format text
```

### 4. Security Monitoring
```bash
# Monitor for potential threats with encrypted storage
niskala --tshark --filter "tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0" --count 1000 --export both --realtime
```

## 🔧 Configuration

### Environment Variables
```bash
export NISKALA_DEFAULT_INTERFACE=eth0
export NISKALA_DEFAULT_WS_PORT=8080
export NISKALA_STORAGE_PATH=/var/captures
```

### Permissions Setup
```bash
# Grant capture capabilities (Linux)
sudo setcap cap_net_raw,cap_net_admin=eip $(which tshark)
sudo setcap cap_net_raw,cap_net_admin=eip $(which niskala)

# Or add user to wireshark group
sudo usermod -a -G wireshark $USER
```

## ⚠️ Important Notes

- **Privileges Required**: Packet capture requires root/administrator privileges
- **Encrypted Storage**: All captures are automatically encrypted with AES-GCM
- **Memory Safety**: Passwords and keys are cleared from memory after use
- **Performance**: Real-time output may impact capture performance on high-traffic networks
- **Legal Compliance**: Ensure you have authorization before capturing network traffic

## 🐛 Troubleshooting

### Common Issues

**"Insufficient privileges for packet capture"**
```bash
# Solution: Grant capabilities or run with sudo
sudo setcap cap_net_raw,cap_net_admin=eip $(which tshark)
```

**"Interface does not exist"**
```bash
# Solution: List available interfaces
ip link show
# Then use: niskala --interface <correct_interface>
```

**"WebSocket connection failed"**
```bash
# Solution: Check if port is available
netstat -ln | grep 8080
# Use different port: niskala --ws-address 0.0.0.0:8081
```

## 📚 Resources

- [Wireshark Documentation](https://www.wireshark.org/docs/)
- [Berkeley Packet Filter (BPF) Guide](https://biot.com/capstats/bpf.html)
- [Network Security Monitoring](https://en.wikipedia.org/wiki/Network_security_monitoring)

## 🤝 Contributing

Contributions welcome! Please focus on defensive security use cases and maintain the security-first design principles.

## 📄 License

MIT License - see LICENSE file for details.
