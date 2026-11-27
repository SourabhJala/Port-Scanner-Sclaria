# Python Multi-Threaded Port Scanner

A Python-based network reconnaissance tool for authorized security testing and lab environments. It scans TCP and UDP ports, identifies common services, attempts banner grabbing, performs basic OS fingerprinting, and exports scan results in multiple formats.

> **Disclaimer:** Use this tool only on systems and networks you own or are explicitly authorized to test. You are responsible for complying with applicable laws, policies, and rules of engagement.

## Features

- **TCP Connect scan (`-sT`)** — default scan method using the operating system's TCP connection interface.
- **TCP SYN scan (`-sS`)** — half-open SYN probing using Scapy and raw packets.
- **TCP FIN, NULL, and Xmas scans (`-sF`, `-sN`, `-sX`)**.
- **UDP scan (`-sU`)** — includes probes for common UDP services such as DNS, NTP, and SNMP.
- **Service identification and banner grabbing** — attempts to identify services and retrieve response banners.
- **Basic OS fingerprinting (`-O`)** — estimates an OS family using observed TTL values and, when available, TCP window information.
- **Concurrent scanning** — uses `ThreadPoolExecutor` to scan ports in parallel.
- **Export formats** — plaintext, JSON, and CSV.
- **Nmap comparison (`--compare-nmap`)** — optionally compares results with a locally installed Nmap binary.
- **Unit tests** — includes tests for port parsing, target resolution, TCP scanning, and report exports.

## Repository Structure

```text
.
├── port_scanner.py
├── PORT_SCANNER_REPORT.md
├── Cybersecurity_Project_Report_Port_Scanner.docx
├── figures/
│   ├── figure1_target_init.png
│   ├── figure2_multithreading.png
│   ├── figure3_tcp_connect.png
│   ├── figure4_syn_stealth.png
│   ├── figure5_stealth_xmas.png
│   ├── figure6_udp_scan.png
│   ├── figure7_banner_os.png
│   └── figure8_nmap_benchmark.png
├── tests/
│   └── test_scanner.py
└── README.md
```

## Requirements

- Python 3.8 or later
- `colorama` (optional; enables colored terminal output)
- `scapy` (optional; required for raw-packet scan modes and raw-packet OS probing)
- Nmap (optional; required only when using `--compare-nmap`)

Install the optional Python dependencies:

```bash
python3 -m pip install colorama scapy
```

The TCP Connect scan can run without Scapy. Raw-packet scan modes generally require administrator/root privileges and Scapy. If Scapy is unavailable or the process lacks the required privileges, the raw TCP scan implementation falls back to a TCP Connect scan. UDP scanning also has a socket-based fallback.

## Installation

Clone the repository and enter the project directory:

```bash
git clone https://github.com/<your-username>/<your-repository>.git
cd <your-repository>
```

No separate build step is required.

## Usage

General syntax:

```bash
python3 port_scanner.py -t <target> [-p <ports>] [scan-options]
```

The target can be an IP address or a hostname.

### Basic TCP scans

Scan the default `top100` port list:

```bash
python3 port_scanner.py -t 127.0.0.1
```

Scan the top 20 ports with verbose output:

```bash
python3 port_scanner.py -t 127.0.0.1 -p top20 -v
```

Scan ports 1–1024:

```bash
python3 port_scanner.py -t 127.0.0.1 -p 1-1024
```

Scan selected ports:

```bash
python3 port_scanner.py -t 127.0.0.1 -p 22,80,443,8080
```

### Other scan modes

Run a TCP SYN scan:

```bash
sudo python3 port_scanner.py -t 192.168.1.10 -p 22,80,443 -sS
```

Run a TCP FIN, NULL, or Xmas scan:

```bash
sudo python3 port_scanner.py -t 192.168.1.10 -p 80,443 -sF
sudo python3 port_scanner.py -t 192.168.1.10 -p 80,443 -sN
sudo python3 port_scanner.py -t 192.168.1.10 -p 80,443 -sX
```

Run a UDP scan:

```bash
sudo python3 port_scanner.py -t 192.168.1.10 -p 53,123,161 -sU
```

Enable OS fingerprinting:

```bash
sudo python3 port_scanner.py -t 192.168.1.10 -p 22,80,443 -O
```

### Tune concurrency and timeout

```bash
python3 port_scanner.py -t 127.0.0.1 -p 1-1024 --threads 150 --timeout 1.5
```

### Export scan results

Save results in plaintext, JSON, and CSV formats:

```bash
python3 port_scanner.py -t 127.0.0.1 -p top100 \
  -oN scan.txt \
  -oJ scan.json \
  -oC scan.csv
```

### Compare with Nmap

If Nmap is installed and available in your system's `PATH`:

```bash
python3 port_scanner.py -t 127.0.0.1 -p 22,80,443 --compare-nmap
```

## Command-Line Options

| Option | Description |
|---|---|
| `-t`, `--target` | Target IP address or hostname (required) |
| `-p`, `--ports` | Ports as a list, range, `top20`, `top100`, or `all`; default is `top100` |
| `-sT` | TCP Connect scan (default) |
| `-sS` | TCP SYN scan |
| `-sU` | UDP scan |
| `-sF` | TCP FIN scan |
| `-sN` | TCP NULL scan |
| `-sX` | TCP Xmas scan |
| `-sV`, `--service-version` | Enable service/banner detection (enabled by default) |
| `-O`, `--os-detect` | Enable basic OS fingerprinting |
| `--threads` | Concurrent worker count (default: 100; maximum: 1,000) |
| `--timeout` | Probe timeout in seconds (default: 1.0) |
| `-v`, `--verbose` | Print discovered open or open/filtered ports while scanning |
| `-oN`, `--output` | Write a plaintext report |
| `-oJ`, `--json` | Write a JSON report |
| `-oC`, `--csv` | Write a CSV report |
| `--compare-nmap` | Compare scan results with Nmap |

Port specifications can be combined, for example: `22,80,443` or `22,80-90,443`.

## Running Tests

From the project directory:

```bash
python3 -m unittest discover -s tests -p "test_*.py" -v
```

The test suite covers port-range parsing, target resolution, TCP open/closed detection using a local mock service, and report export generation. Raw-packet scan modes are not covered by these unit tests.

## Understanding Results and Limitations

- `open` indicates that the scanner received a response consistent with an accessible service.
- `closed` indicates that the target actively refused the connection or returned a response indicating no service is listening.
- `filtered` indicates that filtering or a network condition prevented a conclusive result.
- `open|filtered` means the probe received no response that distinguishes an open port from a filtered one; this is especially relevant to UDP and some TCP flag scans.
- Service names inferred from port numbers are not proof of the actual application. Banner grabbing may fail or return incomplete information.
- TTL-based OS identification is heuristic. Routing, proxies, firewalls, and customized network stacks can affect the observed values.
- UDP scans can be inconclusive because many UDP services do not respond to generic probes.
- Scan speed and accuracy depend on network conditions, target behavior, firewall rules, timeout settings, and thread count.

This project is intended as an educational and reconnaissance utility, not a replacement for a full-featured vulnerability scanner or a comprehensive Nmap assessment.

## Project Documentation

The repository includes a detailed project report in `PORT_SCANNER_REPORT.md`, a Word report in `Cybersecurity_Project_Report_Port_Scanner.docx`, and supporting screenshots in the `figures/` directory.

## Author

**Sourabh Jala**

If you use or adapt this project, please retain appropriate attribution.

## License

No license file is currently included. Unless a license is added to the repository, standard copyright applies and reuse or redistribution is not automatically granted.
