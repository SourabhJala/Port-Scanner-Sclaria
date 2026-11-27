# Labmentix Port Scanner & Network Reconnaissance Suite

An advanced, multi-threaded network port scanner, service auditor, and reconnaissance engine built in Python. Designed for authorized network auditing, diagnostic benchmarking, and cybersecurity training.

---

## 🌟 Key Features

- **Multiple Scanning Modes:**
  - **TCP Connect Scan (`-sT`):** Complete RFC 793 three-way handshake (`SYN` -> `SYN-ACK` -> `ACK`), unprivileged, 100% reliable.
  - **TCP SYN Half-Open Stealth Scan (`-sS`):** Sends raw `SYN`, receives `SYN-ACK`, tears down session with `RST` to evade application-level connection logs (via Scapy raw sockets).
  - **Inverse Stealth Scans (`-sF`, `-sN`, `-sX`):** RFC 793 FIN, NULL, and Xmas Tree scans that exploit closed-port `RST` responses to bypass naive packet filters.
  - **UDP Port Scan (`-sU`):** Stateless probing with protocol-tailored payloads (DNS `version.bind`, NTP v3 client, SNMP v2c) and ICMP Port Unreachable detection.
- **Service Version Detection & Banner Grabbing (`-sV`):**
  - Actively probes open ports with protocol triggers (HTTP `HEAD`, SSH greeting, SMTP `EHLO`, FTP) and extracts software and version strings (e.g. OpenSSH 8.9p1, Apache 2.4.52).
- **OS Fingerprinting via IP TTL (`-O`):**
  - Evaluates response packet Time-To-Live (TTL) and TCP Window metrics to classify remote Operating Systems (Linux ~64, Windows ~128, Cisco/Network ~255).
- **High-Performance Multi-Threading:**
  - Asynchronous worker engine powered by `concurrent.futures.ThreadPoolExecutor` scaling up to 1,000 threads. Achieves scan speeds exceeding **3,500 ports/second**.
- **Multi-Format Reporting:**
  - Terminal colorized output with summary statistics.
  - Export to Plaintext (`-oN`), JSON (`-oJ`), and CSV (`-oC`).
- **Nmap Parity Benchmarking (`--compare-nmap`):**
  - Benchmarks scan results and execution timing directly against `/usr/bin/nmap` to validate 100% port state agreement.
- **Automated Formal Report Compilation (`generate_report.py`):**
  - Automatically compiles the 15-day Labmentix hands-on project report into a styled Word document (`Cybersecurity_Project_Report_Port_Scanner.docx`) with embedded screenshot figures and tables.

---

## 📁 Repository Structure

```
.
├── port_scanner.py                              # Core multi-threaded port scanner CLI & library
├── tests/
│   └── test_scanner.py                         # Automated test suite (socket mocking, parser, exports)
├── generate_report.py                          # Compiles the final docx report using python-docx
├── cybersec_report_template (1).docx           # Original Labmentix report template
├── Cybersecurity_Project_Report_Port_Scanner.docx # Populated formal report (All 9 sections + declaration)
├── PORT_SCANNER_REPORT.md                      # Markdown version of the formal report
├── project.pdf                                 # Labmentix project requirements guide
└── README.md                                   # This technical documentation file
```

---

## 🚀 Quick Start

### 1. Requirements
- Python 3.8+
- Optional dependencies:
  ```bash
  pip install scapy colorama python-docx pillow
  ```

### 2. Basic Scans

Scan default Top 100 ports using standard TCP Connect:
```bash
python3 port_scanner.py -t 127.0.0.1
```

Scan top 20 ports with verbose real-time output:
```bash
python3 port_scanner.py -t 127.0.0.1 -p top20 -v
```

Scan specific port range with 150 worker threads and banner grabbing:
```bash
python3 port_scanner.py -t 127.0.0.1 -p 1-1024 --threads 150 -sV
```

### 3. Advanced Stealth & UDP Scans (Root / Sudo)

TCP SYN Half-Open Stealth Scan:
```bash
sudo python3 port_scanner.py -t 192.168.1.1 -p 22,80,443 -sS
```

TCP Xmas Tree Scan:
```bash
sudo python3 port_scanner.py -t 192.168.1.1 -p 80,443,21 -sX
```

UDP Port Scan with protocol payloads:
```bash
sudo python3 port_scanner.py -t 192.168.1.1 -p 53,123,161 -sU
```

### 4. Exporting Results

Save results to JSON, CSV, and text:
```bash
python3 port_scanner.py -t 127.0.0.1 -p top20 -oJ scan.json -oC scan.csv -oN scan.txt
```

### 5. Benchmark Against Nmap

```bash
python3 port_scanner.py -t 127.0.0.1 -p 22,80,443 --compare-nmap
```

---

## 🧪 Running Automated Tests

Run the unit test suite:
```bash
python3 -m unittest discover -s tests -p "test_*.py" -v
```

Output:
```
test_exports (test_scanner.TestPortScanner) ... ok
test_parse_port_range_hyphen_range (test_scanner.TestPortScanner) ... ok
test_parse_port_range_invalid (test_scanner.TestPortScanner) ... ok
test_parse_port_range_presets (test_scanner.TestPortScanner) ... ok
test_parse_port_range_single_and_list (test_scanner.TestPortScanner) ... ok
test_scan_open_and_closed_ports (test_scanner.TestPortScanner) ... ok
test_target_resolution (test_scanner.TestPortScanner) ... ok

----------------------------------------------------------------------
Ran 7 tests in 0.205s

OK
```

---

## 📄 Generating the Formal Report

To regenerate the formal Word submission document:

```bash
python3 generate_report.py
```

The resulting file is saved as:
`Cybersecurity_Project_Report_Port_Scanner.docx`

---

## 📜 Compliance & Ethics

This tool is engineered exclusively for authorized diagnostic benchmarking, authorized penetration testing, and educational research within controlled lab environments. Never scan unauthorized hosts or production networks without explicit written permission.
