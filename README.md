# CodesHacks - Advanced Reconnaissance Framework

![CodesHacks Logo](https://i.imgur.com/placeholder.png)

A comprehensive web reconnaissance tool for security professionals and penetration testers.

## Features

- **Passive Reconnaissance**:
  - Subdomain enumeration (using Subfinder)
  - Historical URL collection (Wayback Machine)
  - DNS record analysis

- **Active Scanning**:
  - Port scanning
  - Service detection
  - Web technology identification

- **Vulnerability Assessment**:
  - Common vulnerability checks
  - Security header analysis
  - Misconfiguration detection

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/codeshacks.git
cd codeshacks
```

2. Install Python dependencies:
```bash
pip install -r requirements.txt
```

3. Install Subfinder (required for subdomain enumeration):
```bash
wget https://github.com/projectdiscovery/subfinder/releases/download/v2.6.3/subfinder_2.6.3_linux_amd64.zip
unzip subfinder_2.6.3_linux_amd64.zip
chmod +x subfinder
sudo mv subfinder /usr/local/bin/
```

## Usage

```bash
python codeshacks.py [OPTIONS] DOMAIN
```

### Options:
- `--passive`: Passive reconnaissance only
- `--active`: Active scanning
- `--vuln`: Vulnerability scanning
- `--full`: Complete assessment (default)
- `-o OUTPUT`: Custom output directory

### Examples:
```bash
# Basic full assessment
python codeshacks.py example.com

# Passive scan only
python codeshacks.py example.com --passive

# Custom output location
python codeshacks.py example.com --full -o ./results/
```

## Output Structure
Results are organized in timestamped directories containing:
- `subdomain.txt`: Found subdomains
- `wayback.txt`: Historical URLs
- `all_subdomains.txt`: Consolidated results
- Scan-specific reports (for active/vuln scans)

## Requirements
- Python 3.8+
- Subfinder v2.6.3+ (for subdomain enumeration)
- See [requirements.txt](requirements.txt) for Python dependencies

## License
MIT License
