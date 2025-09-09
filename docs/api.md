# API Reference

This document provides detailed information about the CodesHacks API, including classes, methods, and integrations.

## Core Classes

### CodesHacks

Main class that handles CLI interface and orchestrates scanning operations.

```python
class CodesHacks:
    def __init__(self):
        """Initialize CodesHacks instance"""
        pass

    def run(self):
        """Main execution method"""
        pass

    def load_config(self):
        """Load configuration from INI file"""
        pass

    def setup_logging(self):
        """Configure logging"""
        pass

    def parse_arguments(self):
        """Parse command line arguments"""
        pass
```

### Scanner

Core scanning functionality implementation.

```python
class Scanner:
    def __init__(self, config, logger):
        """Initialize Scanner with configuration"""
        pass

    def passive_recon(self, domain, session_dir):
        """Perform passive reconnaissance"""
        pass

    def active_scan(self, domain, subs_file, session_dir):
        """Perform active scanning"""
        pass

    def vuln_scan(self, domain, alive_file, session_dir):
        """Perform vulnerability scanning"""
        pass
```

## Configuration

### Config File Structure
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
SHODAN_API_KEY
CENSYS_API_KEY
VIRUSTOTAL_API_KEY
SECURITYTRAILS_KEY
```

## API Integration

### Shodan Integration
```python
def integrate_shodan(self, api_key):
    """
    Initialize Shodan API client
    
    Args:
        api_key (str): Shodan API key
    
    Returns:
        ShodanAPI: Initialized Shodan client
    """
    from shodan import Shodan
    return Shodan(api_key)
```

### Censys Integration
```python
def integrate_censys(self, api_key):
    """
    Initialize Censys API client
    
    Args:
        api_key (str): Censys API key
    
    Returns:
        CensysAPI: Initialized Censys client
    """
    from censys.search import CensysHosts
    return CensysHosts(api_key)
```

## Scanner Modules

### DNS Scanner
```python
def dns_scan(self, domain):
    """
    Perform DNS enumeration
    
    Args:
        domain (str): Target domain
    
    Returns:
        list: Discovered DNS records
    """
    pass
```

### Port Scanner
```python
def port_scan(self, target, ports=None):
    """
    Scan for open ports
    
    Args:
        target (str): Target host
        ports (list): List of ports to scan
    
    Returns:
        dict: Open ports and services
    """
    pass
```

### Web Scanner
```python
def web_scan(self, url):
    """
    Perform web application scanning
    
    Args:
        url (str): Target URL
    
    Returns:
        dict: Scan results
    """
    pass
```

## Custom Module Development

### Module Template
```python
from scanner import Scanner

class CustomModule:
    def __init__(self, config):
        self.config = config
        self.logger = config.get('logger')
    
    def scan(self, target):
        """
        Custom scanning logic
        
        Args:
            target: Scan target
        
        Returns:
            dict: Scan results
        """
        pass
```

### Module Registration
```python
def register_module(self, module):
    """
    Register a custom scanning module
    
    Args:
        module (CustomModule): Module instance
    """
    pass
```

## Result Handling

### Result Structure
```python
class ScanResult:
    def __init__(self):
        self.findings = []
        self.evidence = {}
        self.metadata = {}
    
    def add_finding(self, finding):
        """Add a scan finding"""
        pass
    
    def add_evidence(self, evidence):
        """Add supporting evidence"""
        pass
```

### Output Formats
```python
def generate_report(self, results, format='txt'):
    """
    Generate scan report
    
    Args:
        results (ScanResult): Scan results
        format (str): Output format (txt, json, html)
    
    Returns:
        str: Path to generated report
    """
    pass
```

## Error Handling

### Exception Classes
```python
class ScannerError(Exception):
    """Base exception for scanner errors"""
    pass

class ConfigError(ScannerError):
    """Configuration related errors"""
    pass

class APIError(ScannerError):
    """API integration errors"""
    pass
```

### Error Handling Example
```python
try:
    scanner = Scanner(config)
    results = scanner.scan(target)
except ConfigError as e:
    logger.error(f"Configuration error: {e}")
except APIError as e:
    logger.error(f"API error: {e}")
except ScannerError as e:
    logger.error(f"Scanner error: {e}")
```

## Utility Functions

### Network Utilities
```python
def is_valid_ip(ip):
    """Check if string is valid IP address"""
    pass

def is_valid_domain(domain):
    """Check if string is valid domain name"""
    pass

def get_ip_for_host(host):
    """Resolve hostname to IP address"""
    pass
```

### File Utilities
```python
def ensure_dir(path):
    """Ensure directory exists"""
    pass

def safe_filename(name):
    """Generate safe filename"""
    pass

def read_wordlist(path):
    """Read wordlist file"""
    pass
```

## Constants and Defaults

### Default Configuration
```python
DEFAULT_CONFIG = {
    'threads': 10,
    'timeout': 10,
    'rate_limit': 50,
    'output_dir': 'results',
    'debug': False
}
```

### Common Ports
```python
COMMON_PORTS = {
    'http': [80, 8080],
    'https': [443, 8443],
    'ftp': [21],
    'ssh': [22],
    'telnet': [23],
    'smtp': [25],
    'dns': [53],
    'mysql': [3306],
    'rdp': [3389]
}
```

## Examples

### Basic Usage
```python
from codeshacks import CodesHacks

scanner = CodesHacks()
scanner.run()
```

### Custom Configuration
```python
config = {
    'threads': 20,
    'timeout': 30,
    'output_dir': 'custom_results',
    'api_keys': {
        'shodan': 'your_key',
        'censys': 'your_key'
    }
}

scanner = CodesHacks()
scanner.config.update(config)
scanner.run()
```

### Custom Module Usage
```python
class CustomScanner(Scanner):
    def custom_scan(self, target):
        results = []
        # Custom scanning logic
        return results

scanner = CustomScanner(config)
results = scanner.custom_scan('example.com')
```
