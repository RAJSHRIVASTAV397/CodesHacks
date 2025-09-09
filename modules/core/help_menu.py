"""Help menu and documentation for CodesHacks tools and scans."""

from typing import Dict, List
import textwrap
from modules.utils.logging import colored_text

# Main categories of tools
CATEGORIES = {
    'recon': 'Reconnaissance Tools',
    'vuln': 'Vulnerability Scanning',
    'web': 'Web Application Testing',
    'network': 'Network Tools',
    'external': 'External Tools Integration',
    'mobile': 'Mobile Application Testing',
    'api': 'API Security Testing',
    'crypto': 'Cryptographic Analysis',
    'malware': 'Malware Analysis',
    'forensics': 'Digital Forensics'
}

# Detailed tool descriptions
TOOLS = {
    'recon': {
        'osint': {
            'name': 'OSINT Gathering',
            'description': 'Open Source Intelligence gathering tools',
            'options': [
                '-t, --target TARGET     Target organization/domain/person',
                '--source SOURCE        Specify OSINT source (shodan/censys/etc)',
                '--api-key KEY         API key for OSINT services',
                '--output DIR          Output directory for results'
            ],
            'example': '''
                # Basic OSINT gathering
                codeshacks.py -t osint -t example.com

                # Use specific OSINT source
                codeshacks.py -t osint -t example.com --source shodan --api-key YOUR_KEY

                # Comprehensive OSINT scan
                codeshacks.py -t osint -t example.com --all-sources
            '''
        },
        'dns': {
            'name': 'DNS Enumeration',
            'description': 'Perform DNS reconnaissance and subdomain discovery',
            'options': [
                '-d, --domain DOMAIN     Target domain name',
                '-w, --wordlist FILE     Wordlist for subdomain bruteforce',
                '--dns-server SERVER     Custom DNS server',
                '--timeout SECONDS       Query timeout'
            ],
            'example': '''
                # Basic DNS enumeration
                codeshacks.py -t dns -d example.com

                # Subdomain bruteforce with custom wordlist
                codeshacks.py -t dns -d example.com -w wordlists/subdomains.txt

                # Use specific DNS server
                codeshacks.py -t dns -d example.com --dns-server 8.8.8.8
            '''
        },
        'whois': {
            'name': 'WHOIS Lookup',
            'description': 'Gather domain registration and ownership information',
            'options': [
                '-d, --domain DOMAIN     Target domain name',
                '--raw                   Show raw WHOIS response'
            ],
            'example': '''
                # Basic WHOIS lookup
                codeshacks.py -t whois -d example.com

                # Get raw WHOIS data
                codeshacks.py -t whois -d example.com --raw
            '''
        }
    },
    'vuln': {
        'port': {
            'name': 'Port Scanner',
            'description': 'Scan for open ports and services',
            'options': [
                '-t, --target TARGET     Target IP or hostname',
                '-p, --ports PORTS       Port specification (e.g., 80,443 or 1-1000)',
                '--timeout SECONDS       Connection timeout',
                '--banner               Attempt banner grabbing'
            ],
            'example': '''
                # Scan common ports
                codeshacks.py -t port-scan -t 192.168.1.1

                # Scan specific port range with banner grabbing
                codeshacks.py -t port-scan -t example.com -p 1-1000 --banner
            '''
        },
        'ssl': {
            'name': 'SSL/TLS Scanner',
            'description': 'Check SSL/TLS configuration and vulnerabilities',
            'options': [
                '-t, --target TARGET     Target hostname',
                '-p, --port PORT         Target port (default: 443)',
                '--json                  Output results in JSON format'
            ],
            'example': '''
                # Basic SSL scan
                codeshacks.py -t ssl-scan -t example.com

                # Scan specific port with JSON output
                codeshacks.py -t ssl-scan -t example.com -p 8443 --json
            '''
        }
    },
    'web': {
        'crawl': {
            'name': 'Web Crawler',
            'description': 'Crawl web applications to map structure and find endpoints',
            'options': [
                '-u, --url URL          Target URL',
                '-d, --depth DEPTH      Maximum crawl depth',
                '--exclude PATTERN      URL patterns to exclude',
                '--cookies FILE         Cookies file for authentication'
            ],
            'example': '''
                # Basic crawl
                codeshacks.py -t crawl -u https://example.com

                # Deep crawl with exclusions
                codeshacks.py -t crawl -u https://example.com -d 3 --exclude "logout|.pdf"
            '''
        },
        'xss': {
            'name': 'XSS Scanner',
            'description': 'Scan for Cross-Site Scripting vulnerabilities',
            'options': [
                '-u, --url URL          Target URL',
                '-p, --payload FILE     Custom XSS payload file',
                '--forms               Test all forms',
                '--headers             Test headers'
            ],
            'example': '''
                # Scan forms for XSS
                codeshacks.py -t xss -u https://example.com --forms

                # Use custom payloads
                codeshacks.py -t xss -u https://example.com -p payloads/xss.txt
            '''
        }
    },
    'network': {
        'traceroute': {
            'name': 'Traceroute',
            'description': 'Trace network path to target',
            'options': [
                '-t, --target TARGET     Target hostname or IP',
                '-m, --max-hops NUM      Maximum number of hops',
                '--timeout SECONDS       Probe timeout'
            ],
            'example': '''
                # Basic traceroute
                codeshacks.py -t traceroute -t example.com

                # Limit to 15 hops
                codeshacks.py -t traceroute -t example.com -m 15
            '''
        }
    },
    'mobile': {
        'android': {
            'name': 'Android Application Testing',
            'description': 'Security assessment of Android applications',
            'options': [
                '-f, --file APK         Path to APK file',
                '--decompile           Decompile APK for analysis',
                '--scan-type TYPE      Type of scan (static/dynamic)',
                '--emulator EMU        Android emulator to use'
            ],
            'example': '''
                # Basic APK analysis
                codeshacks.py -t android -f app.apk

                # Full dynamic analysis
                codeshacks.py -t android -f app.apk --scan-type dynamic --emulator pixel_api_30
            '''
        },
        'ios': {
            'name': 'iOS Application Testing',
            'description': 'Security assessment of iOS applications',
            'options': [
                '-f, --file IPA         Path to IPA file',
                '--jailbreak           Test on jailbroken device',
                '--scan-type TYPE      Type of scan (static/dynamic)',
                '--device ID           iOS device/simulator ID'
            ],
            'example': '''
                # Static IPA analysis
                codeshacks.py -t ios -f app.ipa

                # Dynamic analysis on device
                codeshacks.py -t ios -f app.ipa --scan-type dynamic --device iPhone12_14.5
            '''
        }
    },
    'api': {
        'rest': {
            'name': 'REST API Security Testing',
            'description': 'Test REST API endpoints for security vulnerabilities',
            'options': [
                '-u, --url URL          Base API URL',
                '--spec FILE           API specification file (OpenAPI/Swagger)',
                '--auth TYPE           Authentication type',
                '--token TOKEN         Authentication token'
            ],
            'example': '''
                # Test API endpoints
                codeshacks.py -t rest -u https://api.example.com

                # Test with OpenAPI spec
                codeshacks.py -t rest -u https://api.example.com --spec api.yaml
            '''
        },
        'graphql': {
            'name': 'GraphQL Security Testing',
            'description': 'Security assessment of GraphQL APIs',
            'options': [
                '-u, --url URL          GraphQL endpoint URL',
                '--introspection      Enable introspection queries',
                '--auth TOKEN         Authentication token',
                '--depth DEPTH        Query depth limit'
            ],
            'example': '''
                # Basic GraphQL analysis
                codeshacks.py -t graphql -u https://api.example.com/graphql

                # Full API mapping
                codeshacks.py -t graphql -u https://api.example.com/graphql --introspection
            '''
        }
    },
    'crypto': {
        'cert': {
            'name': 'Certificate Analysis',
            'description': 'Analyze digital certificates and PKI',
            'options': [
                '-f, --file CERT        Certificate file',
                '--chain               Verify certificate chain',
                '--check-revocation   Check revocation status',
                '--export FORMAT      Export format (PEM/DER)'
            ],
            'example': '''
                # Analyze certificate
                codeshacks.py -t cert -f cert.pem

                # Check full chain
                codeshacks.py -t cert -f cert.pem --chain --check-revocation
            '''
        },
        'hash': {
            'name': 'Hash Analysis',
            'description': 'Analyze and crack cryptographic hashes',
            'options': [
                '-h, --hash HASH        Hash to analyze/crack',
                '--type TYPE           Hash type (MD5/SHA/etc)',
                '--wordlist FILE       Password wordlist',
                '--rules FILE         Hash rules file'
            ],
            'example': '''
                # Identify hash type
                codeshacks.py -t hash -h 5f4dcc3b5aa765d61d8327deb882cf99

                # Crack hash with wordlist
                codeshacks.py -t hash -h 5f4dcc3b5aa765d61d8327deb882cf99 --type md5 --wordlist rockyou.txt
            '''
        }
    },
    'malware': {
        'static': {
            'name': 'Static Malware Analysis',
            'description': 'Static analysis of suspicious files',
            'options': [
                '-f, --file FILE        File to analyze',
                '--yara FILE          YARA rules file',
                '--strings            Extract strings',
                '--pe                 PE file analysis'
            ],
            'example': '''
                # Basic static analysis
                codeshacks.py -t static -f suspicious.exe

                # Analysis with custom YARA rules
                codeshacks.py -t static -f suspicious.exe --yara rules.yar
            '''
        },
        'dynamic': {
            'name': 'Dynamic Malware Analysis',
            'description': 'Dynamic analysis in isolated environment',
            'options': [
                '-f, --file FILE        File to analyze',
                '--vm VM              Virtual machine to use',
                '--timeout SECONDS    Analysis timeout',
                '--network           Enable network access'
            ],
            'example': '''
                # Safe dynamic analysis
                codeshacks.py -t dynamic -f suspicious.exe

                # Extended analysis with network
                codeshacks.py -t dynamic -f suspicious.exe --timeout 300 --network
            '''
        }
    },
    'forensics': {
        'disk': {
            'name': 'Disk Forensics',
            'description': 'Analyze disk images and filesystems',
            'options': [
                '-i, --image FILE       Disk image file',
                '--type TYPE           Filesystem type',
                '--carve              Carve deleted files',
                '--timeline           Create filesystem timeline'
            ],
            'example': '''
                # Basic disk analysis
                codeshacks.py -t disk -i disk.img

                # Full forensic analysis
                codeshacks.py -t disk -i disk.img --carve --timeline
            '''
        },
        'memory': {
            'name': 'Memory Forensics',
            'description': 'Analyze memory dumps',
            'options': [
                '-d, --dump FILE        Memory dump file',
                '--profile PROFILE     System profile',
                '--plugin PLUGIN      Volatility plugin',
                '--output DIR         Output directory'
            ],
            'example': '''
                # Basic memory analysis
                codeshacks.py -t memory -d memory.dmp --profile Win10x64

                # Run specific plugin
                codeshacks.py -t memory -d memory.dmp --profile Win10x64 --plugin pslist
            '''
        }
    },
    'external': {
        'nmap': {
            'name': 'Nmap Integration',
            'description': 'Integration with Nmap scanner',
            'options': [
                '-t, --target TARGET     Target specification',
                '-p, --ports PORTS       Port specification',
                '--script SCRIPT         Nmap script to run'
            ],
            'example': '''
                # Basic Nmap scan
                codeshacks.py -t nmap -t 192.168.1.0/24

                # Run specific Nmap script
                codeshacks.py -t nmap -t example.com --script ssl-enum-ciphers
            '''
        },
        'sqlmap': {
            'name': 'SQLMap Integration',
            'description': 'Integration with SQLMap for SQL injection testing',
            'options': [
                '-u, --url URL          Target URL',
                '--data DATA            POST data',
                '--cookie COOKIE        HTTP Cookie header'
            ],
            'example': '''
                # Basic SQLMap scan
                codeshacks.py -t sqlmap -u "http://example.com/page.php?id=1"

                # Scan with cookies
                codeshacks.py -t sqlmap -u "http://example.com/page.php" --cookie "session=abc123"
            '''
        }
    }
}

def print_main_help() -> None:
    """Print the main help menu."""
    banner = """
    CodesHacks - Security Testing Framework
    ======================================
    
    Usage: codeshacks.py [-h] [-t TOOL] [options]
    
    General Options:
      -h, --help            Show this help message
      -t, --tool TOOL       Tool to use
      -v, --verbose         Enable verbose output
      --debug              Enable debug logging
      -o, --output FILE    Output file for results
      --format FORMAT      Output format (text, json, html)
      
    Available Categories:
    """
    
    print(banner)
    
    for cat_id, cat_name in CATEGORIES.items():
        print(f"    {colored_text(cat_id.upper(), 'cyan')}: {cat_name}")
        tools = TOOLS.get(cat_id, {})
        for tool_id, tool_info in tools.items():
            print(f"        {colored_text(tool_id, 'yellow')}: {tool_info['name']}")
    
    print("\nUse -t TOOL --help for detailed tool options")

def print_tool_help(category: str, tool: str) -> None:
    """Print detailed help for a specific tool.
    
    Args:
        category: Tool category
        tool: Tool name
    """
    if category not in TOOLS or tool not in TOOLS[category]:
        print(colored_text("Error: Tool not found", 'red'))
        return
    
    tool_info = TOOLS[category][tool]
    
    print(f"\n{colored_text(tool_info['name'], 'cyan')}")
    print("=" * len(tool_info['name']))
    print(f"\n{tool_info['description']}\n")
    
    print(colored_text("Options:", 'yellow'))
    for option in tool_info['options']:
        print(f"  {option}")
    
    print(colored_text("\nExample Usage:", 'yellow'))
    print(textwrap.dedent(tool_info['example']).strip())

def print_quick_reference() -> None:
    """Print quick reference guide with common commands."""
    quick_ref = """
    Quick Reference Guide
    ====================
    
    Common Scanning Patterns:
    
    1. Basic Reconnaissance
       # Domain reconnaissance
       codeshacks.py -t dns -d example.com
       codeshacks.py -t whois -d example.com
    
    2. Network Scanning
       # Quick port scan
       codeshacks.py -t port-scan -t example.com -p 80,443,8080
       
       # Detailed service enumeration
       codeshacks.py -t port-scan -t example.com -p 1-1000 --banner
    
    3. Web Application Testing
       # Crawl and analyze website
       codeshacks.py -t crawl -u https://example.com --depth 2
       
       # Test for XSS vulnerabilities
       codeshacks.py -t xss -u https://example.com --forms
    
    4. SSL/TLS Analysis
       # Check SSL configuration
       codeshacks.py -t ssl-scan -t example.com
    
    5. Combined Scans
       # Full reconnaissance
       codeshacks.py -t recon -d example.com --dns --whois --ssl
       
       # Web security audit
       codeshacks.py -t webscan -u https://example.com --crawl --xss --sqlmap
    """
    
    print(textwrap.dedent(quick_ref).strip())
