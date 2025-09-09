# CodesHacks - Advanced Reconnaissance Framework

# CodesHacks - Advanced Reconnaissance Framework

A comprehensive web reconnaissance and vulnerability assessment tool for security professionals and penetration testers. CodesHacks provides a modular, extensible platform for performing detailed security assessments of web applications and infrastructure.


## 🚀 Features

### 1. Passive Reconnaissance
- **Subdomain Enumeration**
  - DNS enumeration and zone transfers
  - Integration with Subfinder
  - Historical data from Wayback Machine
- **OSINT Gathering**
  - ASN and organization lookup
  - SSL certificate analysis
  - Third-party API integration (Shodan, Censys)
- **Technology Detection**
  - Web technology fingerprinting
  - Framework identification
  - CMS detection

### 2. Active Scanning
- **Network Analysis**
  - Advanced port scanning (TCP/UDP)
  - Service fingerprinting
  - SSL/TLS analysis
- **Web Enumeration**
  - Directory discovery
  - Virtual host detection
  - API endpoint mapping
- **Visual Analysis**
  - Automated screenshots
  - Visual comparison
  - Technology stack detection

### 3. Vulnerability Assessment
- **Automated Testing**
  - Common web vulnerabilities
  - Misconfigurations
  - Security headers
- **CMS Scanning**
  - WordPress vulnerability assessment
  - Plugin/theme analysis
  - Version detection
- **Custom Scanning**
  - User-defined test cases
  - Custom payloads
  - Targeted assessments

## 📋 Prerequisites

- Python 3.8 or higher
- Git (for cloning repository)
- Optional external tools:
  - Subfinder (subdomain enumeration)
  - Nuclei (vulnerability scanning)
  - WPScan (WordPress scanning)
  - Nikto (web server scanning)
  - GoBuster (directory enumeration)

## 🛠 Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/codeshacks.git
   cd codeshacks
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv .venv
   # Windows
   .venv\Scripts\activate
   # Linux/macOS
   source .venv/bin/activate
   ```

3. Run the automated installer:
   ```bash
   # Linux/macOS
   sudo python install_dependencies.py
   
   # Windows (Run as Administrator)
   python install_dependencies.py
   ```

The installer will automatically:
- Install required Python packages
- Install system dependencies using your package manager
- Install Go-based tools (nuclei, subfinder, etc.)
- Install Rust-based tools (feroxbuster)
- Configure necessary components

Manual installation is still possible using:
```bash
pip install -r requirements.txt
```

For detailed tool information and manual installation instructions, see [docs/tools.md](docs/tools.md).

## 💻 Usage

### Basic Usage
```bash
python codeshacks.py -d example.com [options]
```

### Quick Commands
```bash
# Full assessment (all modules)
python codeshacks.py -d example.com --full

# Passive reconnaissance only
python codeshacks.py -d example.com --passive

# Active scanning only
python codeshacks.py -d example.com --active

# Vulnerability scanning only
python codeshacks.py -d example.com --vuln

# Quick scan with basic checks
python codeshacks.py -d example.com --quick

# Custom module selection
python codeshacks.py -d example.com --custom "dns,web,vuln"
```

### Advanced Options
```bash
# Specify threads and timeout
python codeshacks.py -d example.com --threads 20 --timeout 30

# Use custom wordlists
python codeshacks.py -d example.com --dns-wordlist lists/dns.txt --web-paths lists/paths.txt

# Set API keys
python codeshacks.py -d example.com --shodan-key YOUR_KEY --censys-key YOUR_KEY

# Output control
python codeshacks.py -d example.com --output-format json --min-severity medium
```

## 📁 Output Structure

Results are organized in timestamped directories:
```
results/
└── scan_20250130_123456/
    ├── scans/
    │   ├── passive/
    │   │   ├── subdomains.txt
    │   │   ├── wayback.txt
    │   │   └── technologies.txt
    │   ├── active/
    │   │   ├── ports.txt
    │   │   └── services.txt
    │   └── vulnerabilities/
    │       ├── findings.txt
    │       └── evidence/
    ├── reports/
    │   ├── summary.txt
    │   └── detailed.html
    └── evidence/
        └── screenshots/
```

## 🔧 Configuration

### Config File (codeshacks.ini)
```ini
[SETTINGS]
output_dir = results
threads = 10
timeout = 10
rate_limit = 50
debug = false

[SCAN_OPTIONS]
top_ports = 1000
screenshot_timeout = 10
crawl_depth = 3

[API_KEYS]
shodan = YOUR_KEY
censys = YOUR_KEY
virustotal = YOUR_KEY
```

### Environment Variables
```bash
export SHODAN_API_KEY=your_key
export CENSYS_API_KEY=your_key
export VIRUSTOTAL_API_KEY=your_key
```

## 🧪 Testing

Run the test suite:
```bash
# Run all tests
pytest

# Run specific test file
pytest test_scanner.py

# Run with coverage
pytest --cov=. tests/
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run the test suite
5. Submit a pull request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔐 Security

- Report security vulnerabilities via GitHub Security Advisories
- Follow secure coding practices when contributing
- Keep dependencies updated
- Review security implications of changes

## 📚 Documentation

Full documentation is available in the [docs/](docs/) directory:
- [Installation Guide](docs/installation.md)
- [User Manual](docs/usage.md)
- [API Reference](docs/api.md)
- [Contributing Guidelines](docs/contributing.md)

## 💡 Support

- GitHub Issues: Bug reports and feature requests
- GitHub Discussions: Questions and community support
- Email: support@codeshacks.com
