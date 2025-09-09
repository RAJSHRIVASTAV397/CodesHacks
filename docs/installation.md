# Installation Guide

This guide provides detailed instructions for installing and configuring CodesHacks on various platforms.

## System Requirements

### Minimum Requirements
- Python 3.8 or higher
- 4GB RAM
- 2GB free disk space
- Internet connection for API integrations

### Recommended Requirements
- Python 3.11 or higher
- 8GB RAM
- 10GB free disk space
- High-speed internet connection

## Installation Steps

### 1. Python Environment Setup

#### Windows
1. Download Python from [python.org](https://python.org)
2. Run the installer, check "Add Python to PATH"
3. Open PowerShell and verify:
   ```powershell
   python --version
   ```

#### Linux/Unix
Most systems come with Python preinstalled. If not:
```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv  # Debian/Ubuntu
# or
sudo dnf install python3 python3-pip python3-virtualenv  # Fedora/RHEL
```

#### macOS
1. Install Homebrew if not present:
   ```bash
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
   ```
2. Install Python:
   ```bash
   brew install python
   ```

### 2. Getting the Code

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/codeshacks.git
   cd codeshacks
   ```

2. Create a virtual environment:
   ```bash
   python -m venv .venv
   ```

3. Activate the virtual environment:
   ```bash
   # Windows
   .venv\Scripts\activate
   
   # Linux/macOS
   source .venv/bin/activate
   ```

4. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### 3. External Tools Installation

#### Subfinder
```bash
# Linux
wget https://github.com/projectdiscovery/subfinder/releases/download/v2.6.3/subfinder_2.6.3_linux_amd64.zip
unzip subfinder_2.6.3_linux_amd64.zip
chmod +x subfinder
sudo mv subfinder /usr/local/bin/

# Windows
# Download from https://github.com/projectdiscovery/subfinder/releases
# Extract to a directory in your PATH
```

#### Nuclei
```bash
# Linux
GO111MODULE=on go get -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei

# Windows
# Download from https://github.com/projectdiscovery/nuclei/releases
```

#### WPScan
```bash
# Linux/macOS
gem install wpscan

# Windows
# Install Ruby from https://rubyinstaller.org/
gem install wpscan
```

### 4. Configuration

1. Copy the example config:
   ```bash
   cp config.template.json config.json
   ```

2. Edit config.json with your settings:
   ```json
   {
     "api_keys": {
       "shodan": "your_key",
       "censys": "your_key",
       "virustotal": "your_key"
     },
     "settings": {
       "threads": 10,
       "timeout": 10,
       "rate_limit": 50
     }
   }
   ```

3. Set environment variables (optional):
   ```bash
   # Linux/macOS
   export SHODAN_API_KEY=your_key
   export CENSYS_API_KEY=your_key
   
   # Windows PowerShell
   $env:SHODAN_API_KEY = "your_key"
   $env:CENSYS_API_KEY = "your_key"
   ```

## Verification

1. Check installation:
   ```bash
   python codeshacks.py --version
   ```

2. Run a test scan:
   ```bash
   python codeshacks.py -d example.com --quick
   ```

## Troubleshooting

### Common Issues

1. **ModuleNotFoundError**
   ```
   Solution: Ensure virtual environment is activated and requirements are installed
   ```

2. **Permission Denied**
   ```
   Solution: Use sudo for tool installation or check file permissions
   ```

3. **Tool Not Found**
   ```
   Solution: Ensure external tools are in PATH or correctly installed
   ```

### Getting Help

- Check the [FAQ](faq.md)
- Review [Common Issues](troubleshooting.md)
- Open an issue on GitHub
- Join our community discussions
