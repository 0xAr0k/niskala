# Niskala

_"Invisible/unseen" - encrypted packet capture tool_

Niskala is a Javanese word meaning "invisible" or "unseen". It's a play on words between "Niskalan" and "Wireshark", the two most popular packet capture tools in the world.

An encrypted packet capture tool with Wireshark integration. Automatically encrypts captured network traffic with AES256 and stores it securely.

## Features

- 🔐 **AES256-GCM encryption** for all captured packets
- 📁 **Secure storage** in hidden home directory (`~/.wireshark_secure/`)
- 🔑 **Password-protected** decryption
- 📦 **CLI and GUI modes** (tshark/wireshark integration)
- 🎯 **Flexible filtering** and analysis options
- 🗂️ **File management** (list, open, decrypt)

## Installation

### From Source

1. **Clone and build:**

   ```bash
   git clone https://github.com/0xAr0k/niskala
   cd niskala
   cargo build --release
   ```

2. **Install globally:**

   ```bash
   cargo install --path .
   ```

3. **Use anywhere:**
   ```bash
   niskala --help
   ```

### Prerequisites

- **Rust** (1.70+)
- **Wireshark/tshark** installed:

  ```bash
  # Ubuntu/Debian
  sudo apt install wireshark-qt tshark

  # macOS
  brew install wireshark

  # Arch Linux
  sudo pacman -S wireshark-qt
  ```

## Usage

### Basic Capture (Encrypted)

```bash
# Capture 50 packets on any interface
niskala --tshark --count 50

# Capture on specific interface
niskala --tshark --interface wlan0

# Apply network filter
niskala --tshark --filter "host 192.168.1.1"
```

### View Encrypted Files

```bash
# List all encrypted captures
niskala --list

# Open specific file (prompts for password)
niskala --open capture_1701234567.pcapng.enc
```

### Advanced Analysis

```bash
# Protocol tree breakdown
niskala --tshark --tree --count 20

# Hex dump view
niskala --tshark --hex --count 10

# Custom field extraction
niskala --tshark --fields "ip.src,tcp.port,http.host"
```

### GUI Mode (Unencrypted Warning)

```bash
# Launch Wireshark GUI (shows encryption warning)
niskala --interface wlan0
```

## File Storage

- **Location**: `~/.wireshark_secure/`
- **Format**: `capture_<timestamp>.pcapng.enc`
- **Encryption**: AES256-GCM with random salt/nonce
- **Access**: Password-protected decryption only

## Security Notes

- Original `.pcapng` files are automatically deleted after encryption
- Decrypted files are temporary and cleaned up after viewing
- Passwords must be 8+ characters
- Each file uses unique salt and nonce for encryption

## Examples

```bash
# Quick network monitoring
niskala -t -c 100 -f "port 443"

# List and open captures
niskala -l
niskala -o capture_1701234567.pcapng.enc

# Detailed HTTP analysis
niskala -t -v -T "ip.src,http.request.method,http.host"
```

## License

MIT License - See LICENSE file for details.
