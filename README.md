# DeepNet - Advanced Network Toolkit

## Features

- **Port Scanner**: Scan TCP and UDP ports with configurable ranges, scan types (SYN, Connect, UDP), and thread count.
- **Packet Crafter**: Craft and send custom TCP, UDP, ICMP, or raw packets with user-defined parameters.
- **Packet Sniffer**: Capture and inspect packets on selected network interfaces with optional BPF filtering.

DeepNet is a modern, GUI-based network toolkit written in Rust. It provides advanced tools for port scanning, packet crafting, and packet sniffing, all accessible through an intuitive interface built with [egui](https://github.com/emilk/egui) and [eframe](https://github.com/emilk/eframe).

## Getting Started

### Screenshots

<img src="https://github.com/Enqute/Movie-Management-System/blob/main/Screenshot%20From%202025-07-05%2022-03-01.png?raw=true" alt="" width="100%">

<img src="https://github.com/Enqute/Movie-Management-System/blob/main/Screenshot%20From%202025-07-05%2022-03-06.png?raw=true" alt="" width="100%">

<img src="https://github.com/Enqute/Movie-Management-System/blob/main/Screenshot%20From%202025-07-05%2022-03-32.png?raw=true" alt="" width="100%">

### Prerequisites

- Rust (latest stable recommended)
- Linux (raw socket operations may require root privileges)
- [libpnet](https://github.com/libpnet/libpnet) dependencies

### Building

Clone the repository and build with Cargo:

```sh
git clone https://github.com/HenokEshetu/DeepNet.git
cd DeepNet
cargo build --release
```

### Running

```sh
cargo run --release
```

> **Note:** Some features (like packet crafting and sniffing) require running as root.

## Usage

- **Port Scanner**: Enter the target IP, port range, scan type, and thread count. Click "Start Scan" to begin.
- **Packet Crafter**: Specify source/destination IPs and ports, protocol, payload, count, and delay. Click "Craft and Send".
- **Packet Sniffer**: Select the interface and (optionally) a BPF filter. Click "Start Sniffing" to capture packets.

## Project Structure

- `src/main.rs` - Application entry point and GUI setup
- `src/widgets/` - GUI components for each tool
- `src/scanner.rs` - Port scanning logic
- `src/crafter.rs` - Packet crafting logic
- `src/sniffer.rs` - Packet sniffing logic
- `src/utils.rs` - Utility functions

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Disclaimer

This tool is intended for educational and authorized testing purposes only. Unauthorized use on networks you do not own or have permission to test is strictly prohibited.

---

*Made with Rust and egui.*
