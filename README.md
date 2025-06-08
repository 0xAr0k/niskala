# Niskala

_"Invisible/unseen" - encrypted packet capture tool_

Niskala is a Javanese word meaning "invisible" or "unseen".

## 🛠️ Installation

### Prerequisites

- **Rust** (1.70+)
- **Wireshark/tshark** installed and in PATH:

  ```bash
  # Ubuntu/Debian
  sudo apt install wireshark-qt tshark

  # macOS
  brew install wireshark

  # Arch Linux
  sudo pacman -S wireshark-qt

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

## 📖 Usage

### Command Line Options

```bash
Usage: niskala [OPTIONS]

Options:
  -i, --interface <INTERFACE>  Network interface [default: any]
  -t, --tshark                 Use tshark for encrypted capture
  -f, --filter <FILTER>        Capture filter (BPF syntax)
  -c, --count <COUNT>          Max packets to capture
  -v, --verbose                Show detailed packet analysis
  -x, --hex                    Show hex dump of packets
  -P, --tree                   Show protocol tree breakdown
  -T, --fields <FIELDS>        Show specific fields (comma-separated)
  -l, --list                   List all encrypted capture files
  -o, --open <FILENAME>        Decrypt and open specific file
  -h, --help                   Print help
  -V, --version                Print version
```

### 🔒 Encrypted Capture (Recommended)

```bash
# Basic encrypted capture
cargo run -- --tshark --count 50

# Capture on specific interface
cargo run -- --interface wlan0 --tshark

# Apply BPF filter
cargo run -- --tshark --filter "tcp port 443"

# HTTP traffic analysis
cargo run -- --tshark --filter "port 80" --fields "ip.src,http.request.method,http.host"
```

### 📋 File Management

```bash
# List all encrypted files
cargo run -- --list

# Output example:
# 📋 Listing encrypted capture files...
# Found 2 encrypted capture(s):
# ============================================================
# 📦 a1b2c3d4 (2.1 MB) - 2024-01-15 14:30:22 - Interface: wlan0
# 📦 e5f6g7h8 (0.8 MB) - 2024-01-15 13:45:10 - Interface: any

# Open and decrypt specific file
cargo run -- --open a1b2c3d4
```

### 🔍 Advanced Analysis

```bash
# Protocol tree analysis
cargo run -- --tshark --tree --count 20 --filter "dns"

# Hex dump view
cargo run -- --tshark --hex --count 10 --filter "icmp"

# Verbose packet details
cargo run -- --tshark --verbose --count 5

# Custom field extraction
cargo run -- --tshark --fields "ip.src,ip.dst,tcp.port,http.user_agent"
```

### 🖥️ GUI Mode (Unencrypted)

```bash
# Launch Wireshark GUI (shows warning about no encryption)
cargo run -- --interface wlan0

# Output:
# ⚠️  WARNING: Wireshark GUI mode does not support automatic encryption!
# 💡 Use --tshark flag for encrypted capture, or manually encrypt files later.
# ❓ Continue with GUI mode? (y/N):
```

# Quick HTTPS monitoring

cargo run -- -t -c 100 -f "port 443"

# DNS analysis with custom fields

cargo run -- -t -f "port 53" -T "dns.qry.name,dns.resp.addr"

# Comprehensive network scan

cargo run -- -t -v -P -c 50 -f "not port 22"

# List and manage captures

cargo run -- -l
cargo run -- -o e5f6g7h8

# Interface-specific monitoring

cargo run -- -i eth0 -t -c 200 -f "tcp"

```

I AM IN THE MIDDLE OF REFACTORING THIS SHIT.
```
