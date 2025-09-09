# User Manual

This guide provides comprehensive information on using CodesHacks for web reconnaissance and security assessment.

## Table of Contents
1. [Getting Started](#getting-started)
2. [Basic Usage](#basic-usage)
3. [Advanced Features](#advanced-features)
4. [Working with Results](#working-with-results)
5. [Best Practices](#best-practices)

## Getting Started

### Command Line Interface
The basic syntax for running CodesHacks is:
```bash
python codeshacks.py -d TARGET [options]
```

### Quick Start Examples
```bash
# Basic scan with default options
python codeshacks.py -d example.com

# Passive reconnaissance only
python codeshacks.py -d example.com --passive

# Full scan with custom threads
python codeshacks.py -d example.com --full --threads 20
```

## Basic Usage

### Scan Modes

1. **Quick Scan**
   ```bash
   python codeshacks.py -d example.com --quick
   ```
   - Fast assessment
   - Basic port scanning
   - Common vulnerabilities

2. **Passive Reconnaissance**
   ```bash
   python codeshacks.py -d example.com --passive
   ```
   - DNS enumeration
   - Subdomain discovery
   - Historical data
   - No active probing

3. **Active Scanning**
   ```bash
   python codeshacks.py -d example.com --active
   ```
   - Port scanning
   - Service detection
   - Web crawling

4. **Vulnerability Assessment**
   ```bash
   python codeshacks.py -d example.com --vuln
   ```
   - Security checks
   - Common vulnerabilities
   - Misconfigurations

### Common Options

```bash
# Set output directory
-o, --output DIR

# Number of threads
--threads NUMBER

# Request timeout
--timeout SECONDS

# Custom wordlists
--dns-wordlist FILE
--web-paths FILE

# API Keys
--shodan-key KEY
--censys-key KEY
```

## Advanced Features

### Custom Scanning
Create targeted scans with specific modules:
```bash
python codeshacks.py -d example.com --custom "dns,web,vuln" \
  --dns-wordlist wordlists/dns.txt \
  --web-paths wordlists/paths.txt
```

### Stealth Mode
Reduce scan footprint:
```bash
python codeshacks.py -d example.com --stealth \
  --delay 2000 \
  --threads 3
```

### API Integration
Using external services:
```bash
python codeshacks.py -d example.com \
  --api-services "shodan,censys,virustotal" \
  --shodan-key YOUR_KEY
```

### Output Formats
```bash
# JSON output
python codeshacks.py -d example.com --output-format json

# HTML report
python codeshacks.py -d example.com --output-format html

# Custom report template
python codeshacks.py -d example.com --report-template custom.jinja2
```

## Working with Results

### Output Directory Structure
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

### Interpreting Results

1. **Summary Report**
   - Overview of findings
   - Risk ratings
   - Statistics

2. **Detailed Reports**
   - Complete technical details
   - Evidence and screenshots
   - Remediation suggestions

3. **Raw Data**
   - Individual scan results
   - Tool outputs
   - Log files

## Best Practices

### Scanning Etiquette
1. Respect target's rate limits
2. Use appropriate scanning speeds
3. Honor robots.txt
4. Follow security policies

### Performance Optimization
1. Adjust thread count based on:
   - Target's capacity
   - Your system resources
   - Network conditions

2. Use targeted wordlists:
   - Technology-specific
   - Industry-relevant
   - Custom-generated

### Security Considerations
1. Handle results securely
2. Protect API keys
3. Follow responsible disclosure
4. Document findings professionally

### Resource Management
1. Clean up old results
2. Monitor disk usage
3. Manage log files
4. Archive important findings

## Advanced Topics

### Custom Modules
Create and integrate custom scanning modules:
```python
from scanner import Scanner

class CustomScanner(Scanner):
    def __init__(self, config):
        super().__init__(config)
        
    def custom_scan(self, target):
        # Implementation
        pass
```

### API Integration
Add new API services:
```python
def integrate_new_api(self, api_key):
    try:
        # API integration code
        pass
    except Exception as e:
        self.logger.error(f"API Error: {str(e)}")
```

### Custom Reports
Create custom report templates:
```jinja2
{% extends "base.html" %}
{% block content %}
  <h1>Custom Scan Report</h1>
  {% for finding in findings %}
    <!-- Custom formatting -->
  {% endfor %}
{% endblock %}
```

## Troubleshooting

### Common Issues

1. **Scan Timeouts**
   ```
   Solution: Adjust --timeout and --threads
   ```

2. **Memory Usage**
   ```
   Solution: Reduce concurrent operations
   ```

3. **Rate Limiting**
   ```
   Solution: Use --rate-limit or --delay
   ```

### Debug Mode
Enable verbose output:
```bash
python codeshacks.py -d example.com --debug
```

## Additional Resources

- [API Reference](api.md)
- [Configuration Guide](configuration.md)
- [Contributing Guidelines](contributing.md)
- [FAQ](faq.md)

## Support

For assistance:
- Open GitHub Issues
- Join Community Discussions
- Contact: support@codeshacks.com
