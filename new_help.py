    def show_help(self):
        """Display the comprehensive help menu"""
        help_text = '''
=================================================================
                    CodesHacks v%(version)s                          
        Advanced Web Reconnaissance & Vulnerability Scanner        
                    Author: %(author)s                    
=================================================================

DESCRIPTION:
    CodesHacks is a comprehensive web security assessment tool that combines
    reconnaissance, scanning, and vulnerability detection capabilities.

BASIC USAGE:
    codeshacks.py -d <domain> [scan mode] [options]

SCAN MODES:
    --passive    Passive reconnaissance only (DNS, subdomains, etc.)
    --active     Active scanning (ports, services, web technologies)
    --vuln       Vulnerability assessment
    --full      Complete assessment (all of the above)
    --quick     Fast scan with basic checks
    --stealth   Stealthy scan with delayed requests

EXAMPLES:
    1. Basic Passive Scan:
       codeshacks.py -d example.com --passive

    2. Full Scan with Maximum Threads:
       codeshacks.py -d example.com --full --threads 50

    3. Vulnerability Scan with Custom Wordlist:
       codeshacks.py -d example.com --vuln -w /path/to/wordlist.txt

    4. Active Scan with Specific Ports:
       codeshacks.py -d example.com --active --ports 80,443,8080-8090

    5. Stealth Mode with Rate Limiting:
       codeshacks.py -d example.com --stealth --rate-limit 10 --delay 2000

DETAILED OPTIONS:
    TARGET OPTIONS:
        -d, --domain       Target domain or IP (required)
        --scope           Define scan scope (e.g., *.domain.com)
        --exclude         Exclude patterns (comma-separated)
        --include         Include only specific patterns

    SCAN CONTROL:
        --threads         Number of concurrent threads
        --timeout        Request timeout in seconds
        --rate-limit     Maximum requests per second
        --delay         Delay between requests (milliseconds)
        --retry         Number of retry attempts

    OUTPUT OPTIONS:
        -o, --output     Output directory
        -v, --verbose    Verbose output
        --debug         Enable debug logging
        --quiet        Minimal output
        --json         Generate JSON output
        --html         Generate HTML report

    API CONFIGURATION:
        --shodan-key     Shodan API key
        --censys-key     Censys API key
        --virustotal-key VirusTotal API key

    ADVANCED OPTIONS:
        --custom-dns     Use custom DNS servers
        --proxy         Use proxy (e.g., http://127.0.0.1:8080)
        --cookies       Load cookies from file
        --user-agent    Custom User-Agent string

MODULES INFORMATION:
    - DNS Scanner: Subdomain enumeration, zone transfers
    - Port Scanner: Service detection, banner grabbing
    - Web Scanner: Technology detection, directory brute-force
    - Vuln Scanner: Common web vulnerabilities, misconfigurations
    
OUTPUT STRUCTURE:
    scan_[timestamp]/
    ├── logs/          - Activity and debug logs
    ├── results/       - Scan findings and data
    ├── evidence/      - Screenshots and proofs
    └── reports/       - Final reports (JSON, HTML, TXT)

For detailed documentation and updates, visit:
https://github.com/RAJSHRIVASTAV397/CodesHacks
'''
        print(help_text % {'version': self.version, 'author': TOOL_INFO['author']})
