# Tools Documentation

## Unified Tools System

The UnifiedTools class provides a comprehensive security assessment toolkit that integrates various security testing tools into a single, easy-to-use interface.

### Categories of Tools

1. Core Security Tools
- Network Scanning: nmap, masscan
- DNS Enumeration: dnsrecon, amass, subfinder
- Web Scanning: nuclei, nikto, wpscan
- Directory Enumeration: feroxbuster, ffuf, gobuster
- Vulnerability Scanning: nuclei, dalfox (XSS)

2. Advanced Security Tools
- Web Application Testing: burpsuite, zap, arachni
- Network Security: metasploit, wireshark, hydra
- Forensics: volatility, autopsy, sleuthkit
- Reverse Engineering: ghidra, radare2, ida
- Cloud Security: cloudsploit, prowler, pacu
- Mobile Security: mobsf, apktool, frida
- IoT Security: firmwalker, binwalk
- Container Security: trivy, grype, syft

### Installation

```bash
# Prerequisites
python -m pip install -r requirements.txt

# The tool will automatically attempt to install missing external tools
# You can also manually trigger installation:
python codeshacks.py --install-tools
```

### Usage Examples

1. Basic Vulnerability Scan:
```python
tools = UnifiedTools()
results = tools.run_nuclei("example.com")
```

2. Comprehensive Web Scan:
```python
tools = UnifiedTools()
subdomain_results = tools.run_subfinder("example.com")
web_scan = tools.run_nuclei(subdomain_results)
xss_scan = tools.run_dalfox(subdomain_results)
```

3. Mobile App Analysis:
```python
tools = UnifiedTools()
results = tools.run_mobsf_analysis("app.apk")
```

4. Container Security:
```python
tools = UnifiedTools()
results = tools.run_trivy_scan("nginx:latest")
```

### Adding New Tools

To add a new tool to the unified system:

1. Add the tool to the `tools` dictionary in `__init__`
2. Create an installation method if needed
3. Implement a run method following the standard pattern
4. Update documentation

Example:
```python
def run_new_tool(self, target: str) -> Optional[str]:
    """Run new security tool.
    
    Args:
        target: Target to scan
        
    Returns:
        Path to output file if successful
    """
    output_file = os.path.join(self.output_dir, 
                              f"newtool_{self._timestamp()}.txt")
    try:
        subprocess.run(['newtool', target, '-o', output_file], check=True)
        return output_file
    except subprocess.CalledProcessError as e:
        self.logger.error(f"New tool failed: {str(e)}")
        return None
```

### Best Practices

1. Always check tool availability before running
2. Handle errors gracefully and provide meaningful error messages
3. Use standardized output formats where possible
4. Implement proper logging for debugging
5. Follow security best practices when running tools
6. Respect rate limits and target policies
