"""
CodesHacks - Security Assessment Framework

This module provides comprehensive security scanning capabilities:
1. Passive Reconnaissance
   - DNS enumeration and zone transfers
   - Subdomain discovery
   - Historical data gathering
   - Technology stack detection

2. Active Scanning
   - Port scanning and service detection
   - Web technology fingerprinting
   - Directory enumeration
   - CMS detection and analysis
   - SSL/TLS analysis

3. Vulnerability Assessment
   - Web server vulnerability scanning
   - SQL injection testing
   - Cross-site scripting (XSS) detection
   - Directory traversal checking
   - CMS-specific vulnerability scanning
   - SSL/TLS configuration analysis
   - Custom payload testing
   - Information disclosure detection

Supported Tools:
- Nmap: Advanced port scanning and service detection
- Nikto: Web server vulnerability scanning
- SQLMap: SQL injection testing
- WPScan: WordPress vulnerability assessment
- GoBuster/Dirb: Directory enumeration
- SSLyze: SSL/TLS analysis
- Nuclei: Vulnerability scanning
- WhatWeb: Web technology detection
- Droopescan: CMS vulnerability scanning
- Skipfish: Web application security assessment
- Arachni: Web application vulnerability scanning

Usage:
    scanner = Scanner(config, logger)
    
    # Quick Scan
    scanner.quick_scan(domain)
    
    # Full Scan with all tools
    scanner.full_scan(domain)
    
    # Custom Scan with specific tools
    scanner.custom_scan(domain, tools=['nmap', 'nikto', 'sqlmap'])

Scan Modes:
1. Quick Scan (-q, --quick)
   - Basic port scanning
   - Common vulnerability checks
   - Fast subdomain enumeration
   - Basic web checks

2. Full Scan (-f, --full)
   - Comprehensive port scanning
   - Deep vulnerability assessment
   - Extensive subdomain enumeration
   - All available security tools
   - Custom payload testing

3. Custom Scan (-c, --custom)
   - Select specific tools
   - Custom wordlists
   - Target specific vulnerabilities
   - Configure scan intensity

Additional Options:
  -t, --threads NUMBER     Number of concurrent threads (default: 10)
  -w, --wordlist FILE     Custom wordlist for directory scanning
  -o, --output DIR        Output directory for scan results
  --timeout SECONDS       Timeout for individual scans (default: 300)
  --rate-limit NUMBER     Maximum requests per second (default: 50)
  
Advanced Options:
  --proxy URL            Use proxy for all requests
  --cookies FILE         Load cookies from file
  --user-agent STRING    Custom User-Agent string
  --follow-redirects     Follow redirects in requests
  --max-depth NUMBER     Maximum directory depth to scan
  --exclude PATTERN      Skip paths matching pattern
  --include PATTERN      Only scan paths matching pattern
  
Examples:
  # Quick scan of a domain
  python scanner.py -q example.com
  
  # Full scan with custom threads and output
  python scanner.py -f example.com -t 20 -o /path/to/output
  
  # Custom scan with specific tools
  python scanner.py -c example.com --tools nmap,nikto,sqlmap
  
  # Advanced scan with proxy and custom wordlist
  python scanner.py -f example.com --proxy http://proxy:8080 -w wordlist.txt
"""

import os
import sys
import socket
import configparser
import logging
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from datetime import datetime
import requests
from concurrent.futures import ThreadPoolExecutor
import json
import subprocess
from urllib.parse import urljoin, urlparse
import dns.resolver
import dns.zone
import nmap
from bs4 import BeautifulSoup
import aiohttp
import asyncio
import re

# Optional imports
HAS_SQLMAP = False  # sqlmap is an external tool, not a Python module
try:
    from vulners import Vulners
    HAS_VULNERS = True
except ImportError:
    HAS_VULNERS = False

try:
    from shodan import Shodan
    HAS_SHODAN = True
except ImportError:
    HAS_SHODAN = False

try:
    from censys.search import CensysHosts
    HAS_CENSYS = True
except ImportError:
    HAS_CENSYS = False

class Scanner:
    def setup_chromedriver(self):
        """Configure ChromeDriver for screenshots"""
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            from selenium.webdriver.chrome.service import Service
            from webdriver_manager.chrome import ChromeDriverManager
            
            # Configure Chrome options
            chrome_options = Options()
            chrome_options.add_argument("--headless")  # Run in headless mode
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--window-size=1920,1080")
            chrome_options.add_argument("--disable-gpu")
            chrome_options.add_argument("--ignore-certificate-errors")
            
            # Automatically download and setup ChromeDriver
            service = Service(ChromeDriverManager().install())
            driver = webdriver.Chrome(service=service, options=chrome_options)
            driver.set_page_load_timeout(self.timeout)
            
            return driver
        except Exception as e:
            self.logger.error(f"Failed to setup ChromeDriver: {str(e)}")
            return None

    def __init__(self, config, logger):
        """Initialize scanner with configuration and logger"""
        try:
            self.config = config
            self.logger = logger
            
            # Log initial configuration
            self.logger.debug(f"Initial config: {config}")
            
            self.api_keys = config.get('api_keys', {})
            self.threads = config.get('threads', 10)
            self.timeout = config.get('timeout', 10)
            self.rate_limit = config.get('rate_limit', 50)
            
            # Set up base directory
            base_dir = os.path.dirname(os.path.abspath(__file__))
            self.logger.debug(f"Base directory: {base_dir}")
            
            # Get output directory from config
            self.results_dir = config.get('output_dir', os.path.join(base_dir, 'results'))
            self.logger.debug(f"Results directory: {self.results_dir}")
            
            # Ensure results directory exists
            os.makedirs(self.results_dir, exist_ok=True)
            
            # Create results directory
            try:
                if not os.path.exists(self.results_dir):
                    self.logger.debug(f"Creating results directory: {self.results_dir}")
                    os.makedirs(self.results_dir)
                    self.logger.info(f"Created results directory: {self.results_dir}")
                else:
                    self.logger.debug(f"Results directory already exists: {self.results_dir}")
            except Exception as e:
                self.logger.error(f"Error creating results directory: {str(e)}")
                raise
            
            # Initialize scan session
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            self.session_dir = os.path.join(self.results_dir, f"scan_{timestamp}")
            self.logger.debug(f"Session directory path: {self.session_dir}")
            
            # Create session directory
            try:
                os.makedirs(self.session_dir, exist_ok=True)
                self.logger.info(f"Created/verified session directory: {self.session_dir}")
            except Exception as e:
                self.logger.error(f"Error creating session directory: {str(e)}")
                raise
            
            # Create report subdirectories
            try:
                for subdir in ['scans', 'reports', 'evidence']:
                    path = os.path.join(self.session_dir, subdir)
                    os.makedirs(path, exist_ok=True)
                    self.logger.debug(f"Created subdirectory: {path}")
            except Exception as e:
                self.logger.error(f"Error creating subdirectories: {str(e)}")
                raise
                
            # Log successful initialization
            self.logger.info("Scanner initialized successfully")
            self.logger.info(f"Results will be saved to: {self.session_dir}")
            
        except Exception as e:
            self.logger.error(f"Error initializing scanner: {str(e)}")
            raise
        
        # Initialize default wordlists
        self.default_wordlists = {
            'directories': [
                'admin', 'wp-admin', 'administrator', 'login', 'wp-login.php',
                'backup', 'backups', 'data', 'db', 'database', 'dev', 'development',
                'staging', 'test', 'testing', 'api', 'v1', 'v2', 'v3', 'beta',
                'config', 'settings', 'setup', 'install', 'wp-config.php',
                'upload', 'uploads', 'files', 'images', 'img', 'css', 'js',
                'php', 'includes', 'inc', 'logs', 'log', 'temp', 'tmp',
                'private', 'secret', 'hidden', 'admin_panel', 'dashboard',
                'phpmyadmin', 'mysql', 'sql', 'ftp', 'ssh', 'webmail',
                '.git', '.svn', '.htaccess', '.env', 'robots.txt', 'sitemap.xml',
                'readme', 'readme.txt', 'readme.md', 'license', 'license.txt',
                'changelog', 'changelog.txt', 'wp-content', 'wp-includes'
            ],
            'subdomains': [
                'www', 'mail', 'webmail', 'ftp', 'smtp', 'pop', 'pop3', 'imap',
                'admin', 'administrator', 'blog', 'blogs', 'dev', 'development',
                'stage', 'staging', 'prod', 'production', 'test', 'testing',
                'demo', 'portal', 'shop', 'store', 'api', 'api1', 'api2',
                'cdn', 'cdn1', 'cdn2', 'static', 'assets', 'media', 'download',
                'downloads', 'apps', 'app', 'mobile', 'm', 'secure', 'vpn',
                'remote', 'support', 'help', 'kb', 'docs', 'documentation',
                'wiki', 'auth', 'login', 'db', 'database', 'mysql', 'oracle',
                'ns1', 'ns2', 'dns1', 'dns2', 'mx1', 'mx2', 'email', 'mail2'
            ],
            'common_files': [
                'index.php', 'index.html', 'index.htm', 'default.php',
                'default.html', 'default.htm', 'home.php', 'home.html',
                'wp-config.php', 'configuration.php', 'config.php', 'config.inc.php',
                'settings.php', 'setup.php', 'install.php', 'wp-login.php',
                'admin.php', 'administrator.php', 'admin.html', 'login.php',
                'login.html', 'phpinfo.php', 'info.php', 'test.php', '.env',
                '.htaccess', 'web.config', 'robots.txt', 'sitemap.xml',
                'backup.sql', 'dump.sql', 'database.sql', 'backup.zip',
                'backup.tar.gz', 'wp-config.php.bak', 'config.php.bak'
            ]
        }
        
    def get_wordlist(self, wordlist_type, custom_wordlist=None):
        """
        Get the appropriate wordlist based on type and availability.
        
        Args:
            wordlist_type: Type of wordlist ('directories', 'subdomains', 'common_files')
            custom_wordlist: Path to custom wordlist file (optional)
            
        Returns:
            list: List of words to use for scanning
        """
        if custom_wordlist:
            try:
                if os.path.exists(custom_wordlist):
                    self.logger.info(f"Using custom wordlist: {custom_wordlist}")
                    with open(custom_wordlist, 'r', encoding='utf-8') as f:
                        return [line.strip() for line in f if line.strip()]
                else:
                    self.logger.warning(f"Custom wordlist not found: {custom_wordlist}")
            except Exception as e:
                self.logger.error(f"Error reading custom wordlist: {str(e)}")
        
        # Use default wordlist if custom one is not available
        if wordlist_type in self.default_wordlists:
            self.logger.info(f"Using default {wordlist_type} wordlist")
            return self.default_wordlists[wordlist_type]
        
        self.logger.error(f"Unknown wordlist type: {wordlist_type}")
        return []

    def passive_recon(self, domain, session_dir):
        """Perform passive reconnaissance including subdomain enumeration"""
        self.logger.info(f"\nStarting passive reconnaissance for {domain}")
        
        # Primary subdomain enumeration using DNS
        self.logger.info("Enumerating primary subdomains...")
        subdomains_file = os.path.join(session_dir, "subdomain.txt")
        subdomains = set()
        
        # Common DNS record types to check
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS']
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout
        
        # Try zone transfer first
        try:
            answers = resolver.resolve(domain, 'NS')
            for ns in answers:
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(str(ns), domain))
                    for name, _ in zone.nodes.items():
                        subdomain = str(name) + '.' + domain
                        if subdomain.startswith('@.'):
                            subdomain = domain
                        subdomains.add(subdomain)
                except:
                    continue
        except:
            pass

        # Get subdomain wordlist (use custom if provided in config)
        custom_subdomain_list = self.config.get('wordlists', {}).get('subdomains')
        common_prefixes = self.get_wordlist('subdomains', custom_subdomain_list)

        # Try common subdomains
        for prefix in common_prefixes:
            subdomain = f"{prefix}.{domain}"
            for record_type in record_types:
                try:
                    answers = resolver.resolve(subdomain, record_type)
                    subdomains.add(subdomain)
                    # If we find a valid subdomain, also try to get its CNAME
                    try:
                        cname_answers = resolver.resolve(subdomain, 'CNAME')
                        for rdata in cname_answers:
                            subdomains.add(str(rdata.target).rstrip('.'))
                    except:
                        pass
                    break
                except:
                    continue

        # Secondary subdomain enumeration - try variations
        self.logger.info("Enumerating second-level subdomains...")
        subs_file = os.path.join(session_dir, "subs.txt")
        secondary_subdomains = set()
        for sub in subdomains:
            for prefix in ['dev', 'test', 'staging', 'beta', 'alpha']:
                second_level = f"{prefix}.{sub}"
                try:
                    answers = resolver.resolve(second_level, 'A')
                    secondary_subdomains.add(second_level)
                except:
                    continue

        # Historical URL gathering using Wayback Machine API
        self.logger.info("Gathering historical URLs...")
        wayback_file = os.path.join(session_dir, "wayback.txt")
        wayback_subs = set()
        try:
            wayback_url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&fl=original&collapse=urlkey"
            response = requests.get(wayback_url, timeout=self.timeout)
            if response.status_code == 200:
                urls = response.json()
                if urls and len(urls) > 1:  # First row is header
                    for url in urls[1:]:
                        try:
                            parsed = re.match(r'https?://([^/]+)', url[0])
                            if parsed:
                                subdomain = parsed.group(1)
                                if subdomain.endswith(domain):
                                    wayback_subs.add(subdomain)
                        except:
                            continue
        except:
            self.logger.warning("Failed to fetch Wayback Machine data")

        # Write results to files
        with open(subdomains_file, 'w') as f:
            f.write('\n'.join(sorted(subdomains)))

        with open(subs_file, 'w') as f:
            f.write('\n'.join(sorted(secondary_subdomains)))

        with open(wayback_file, 'w') as f:
            f.write('\n'.join(sorted(wayback_subs)))

        # Consolidate results
        self.logger.info("Consolidating subdomains...")
        all_subs_file = os.path.join(session_dir, "all_subdomains.txt")
        all_subdomains = subdomains | secondary_subdomains | wayback_subs
        
        with open(all_subs_file, 'w') as f:
            f.write('\n'.join(sorted(all_subdomains)))
        
        self.logger.info(f"Found {len(all_subdomains)} unique subdomains")
        
        # Cleanup intermediate files
        for f in [subdomains_file, subs_file, wayback_file]:
            if os.path.exists(f):
                os.remove(f)
        
        return all_subs_file

    def active_scan(self, domain, subs_file, session_dir):
        """Perform active scanning including port scanning and web crawling"""
        self.logger.info(f"\nStarting active scanning for {domain}")
        
        # Verify live hosts
        self.logger.info("Checking for live hosts...")
        alive_file = os.path.join(session_dir, "alive.txt")
        self.check_live_hosts(subs_file, alive_file)
        
        # Port scanning
        self.logger.info("Scanning for open ports...")
        ports_file = os.path.join(session_dir, "ports.txt")
        self.scan_ports(alive_file, ports_file)
        
        # Web technology detection
        self.logger.info("Detecting web technologies...")
        tech_file = os.path.join(session_dir, "tech.txt")
        self.detect_tech(alive_file, tech_file)
        
        # Web crawling and screenshotting
        self.logger.info("Crawling websites and taking screenshots...")
        screenshots_dir = os.path.join(session_dir, "screenshots")
        self.crawl_and_screenshot(alive_file, screenshots_dir)
        
        return alive_file

    def vuln_scan(self, domain, alive_file, session_dir):
        """Perform comprehensive vulnerability scanning with multiple tools"""
        self.logger.info(f"\nStarting comprehensive vulnerability scanning for {domain}")

        # Create directory for all scan results
        scan_dir = os.path.join(session_dir, "vulnerability_scans")
        os.makedirs(scan_dir, exist_ok=True)

        # Load live hosts
        with open(alive_file, 'r') as f:
            hosts = [line.strip() for line in f if line.strip()]

        all_findings = []

        # Step 1: Generate custom payloads
        self.logger.info("Generating custom payloads...")
        payloads_dir = os.path.join(scan_dir, "payloads")
        self.generate_payloads(payloads_dir)

        # Step 2: Prepare common wordlist
        wordlist = os.path.join(scan_dir, "wordlist.txt")
        with open(wordlist, 'w') as f:
            f.write('\n'.join([
                'admin', 'wp-admin', 'login', 'wp-login.php', 'administrator',
                'backup', 'db', 'sql', 'dev', 'test', 'api', 'v1', 'v2',
                'config', 'settings', 'upload', 'uploads', 'files', 'images',
                'php.ini', '.env', '.git', 'robots.txt', 'sitemap.xml',
                'index.php', 'wp-config.php', '.htaccess', 'web.config',
                'backup.zip', 'backup.sql', 'admin.php', 'phpinfo.php',
                'test.php', 'info.php', 'database.sql', '.svn', '.DS_Store'
            ]))

        for host in hosts:
            self.logger.info(f"\nScanning {host}...")
            host_dir = os.path.join(scan_dir, urlparse(host).netloc)
            os.makedirs(host_dir, exist_ok=True)

            # Step 3: Nikto Web Server Scan
            nikto_file = os.path.join(host_dir, "nikto_results.txt")
            if self.scan_with_nikto(host, nikto_file):
                self.logger.info("Nikto scan completed")
                with open(nikto_file) as f:
                    all_findings.extend(f"[Nikto] {line.strip()}" for line in f if "+" in line)

            # Step 4: Directory Enumeration with GoBuster
            gobuster_file = os.path.join(host_dir, "gobuster_results.txt")
            if self.scan_with_gobuster(host, wordlist, gobuster_file):
                self.logger.info("Directory enumeration completed")
                with open(gobuster_file) as f:
                    interesting = [line.strip() for line in f 
                                if any(word in line.lower() 
                                    for word in ['admin', 'config', 'backup', 'db', '.git'])]
                    if interesting:
                        all_findings.extend(f"[GoBuster] Found sensitive path: {line}" for line in interesting)

            # Step 5: WordPress Specific Scans
            if asyncio.run(self.is_wordpress(host)):
                wp_file = os.path.join(host_dir, "wpscan_results.txt")
                if self.scan_with_wpscan(host, wp_file):
                    self.logger.info("WordPress scan completed")
                    with open(wp_file) as f:
                        all_findings.extend(f"[WPScan] {line.strip()}" 
                                        for line in f if '[+]' in line or '[!]' in line)

            # Step 6: SQL Injection Testing
            sqlmap_dir = os.path.join(host_dir, "sqlmap")
            if self.scan_with_sqlmap(host, sqlmap_dir):
                self.logger.info("SQL injection testing completed")
                for root, _, files in os.walk(sqlmap_dir):
                    for file in files:
                        if file.endswith('.txt'):
                            with open(os.path.join(root, file)) as f:
                                content = f.read()
                                if 'Parameter:' in content:
                                    all_findings.append(f"[SQLMap] SQL injection found in {file}")

            # Step 7: SSL/TLS Configuration Check
            if host.startswith('https://'):
                ssl_file = os.path.join(host_dir, "sslyze_results.json")
                if self.scan_with_sslyze(urlparse(host).netloc, ssl_file):
                    self.logger.info("SSL/TLS scan completed")
                    with open(ssl_file) as f:
                        ssl_data = json.load(f)
                        for finding in ssl_data.get('server_scan_results', []):
                            if finding.get('scan_status') == 'ERROR':
                                all_findings.append(
                                    f"[SSLyze] {finding.get('scan_result', {}).get('error_message')}"
                                )

            # Step 8: Run Built-in Python Scanners
            vuln_file = os.path.join(host_dir, "vulnerabilities.txt")
            self.scan_vulnerabilities(alive_file, vuln_file, payloads_dir)
            with open(vuln_file) as f:
                all_findings.extend(line.strip() for line in f if line.strip())

        # Step 9: Generate Comprehensive Report
        self.logger.info("\nGenerating comprehensive report...")
        report_file = os.path.join(session_dir, "comprehensive_report.txt")
        
        with open(report_file, 'w') as f:
            f.write("CodesHacks Comprehensive Security Assessment Report\n")
            f.write("=" * 60 + "\n\n")
            f.write(f"Report Generated: {datetime.now()}\n")
            f.write(f"Target Domain: {domain}\n")
            f.write(f"Hosts Scanned: {len(hosts)}\n\n")

            # Categorize findings
            categories = {
                'CRITICAL': [], 'HIGH': [], 'MEDIUM': [], 'LOW': [],
                'INFO': [], 'UNKNOWN': []
            }

            tool_stats = {
                'Nikto': 0, 'GoBuster': 0, 'WPScan': 0,
                'SQLMap': 0, 'SSLyze': 0, 'Built-in': 0
            }

            for finding in all_findings:
                # Count by tool
                for tool in tool_stats:
                    if f"[{tool}]" in finding:
                        tool_stats[tool] += 1
                        break

                # Categorize by severity
                if 'CRITICAL' in finding:
                    categories['CRITICAL'].append(finding)
                elif 'HIGH' in finding:
                    categories['HIGH'].append(finding)
                elif 'MEDIUM' in finding:
                    categories['MEDIUM'].append(finding)
                elif 'LOW' in finding:
                    categories['LOW'].append(finding)
                elif 'INFO' in finding:
                    categories['INFO'].append(finding)
                else:
                    categories['UNKNOWN'].append(finding)

            # Write Executive Summary
            f.write("Executive Summary\n")
            f.write("-" * 30 + "\n")
            f.write(f"Total Findings: {len(all_findings)}\n\n")
            
            f.write("Severity Distribution:\n")
            for sev, items in categories.items():
                if items:
                    f.write(f"- {sev}: {len(items)}\n")
            f.write("\n")

            f.write("Tools Summary:\n")
            for tool, count in tool_stats.items():
                if count > 0:
                    f.write(f"- {tool}: {count} findings\n")
            f.write("\n")

            # Write Detailed Findings
            f.write("\nDetailed Findings\n")
            f.write("=" * 30 + "\n\n")

            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNKNOWN']:
                if categories[severity]:
                    f.write(f"\n{severity} Severity Findings:\n")
                    f.write("-" * 30 + "\n")
                    for finding in categories[severity]:
                        f.write(f"{finding}\n")
                    f.write("\n")

        self.logger.info(f"Comprehensive report generated: {report_file}")
        return report_file

    def check_tool_installed(self, tool):
        """Check if a required tool is installed"""
        try:
            subprocess.run([tool, '--version'], capture_output=True, check=True)
            return True
        except (subprocess.SubprocessError, FileNotFoundError):
            return False

    def run_subfinder(self, domain, output_file):
        """Run subdomain enumeration using subfinder with better fallback"""
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        if not self.check_tool_installed('subfinder'):
            self.logger.warning("subfinder not installed - using built-in enumeration")
            with open(output_file, 'w') as f:
                f.write(f"www.{domain}\nmail.{domain}\napi.{domain}\n")
            return
                
        try:
            self.logger.info(f"Running subfinder on {domain}...")
            result = subprocess.run(
                ['subfinder', '-d', domain, '-o', output_file],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                with open(output_file, 'r') as f:
                    subdomains = f.readlines()
                self.logger.info(f"Found {len(subdomains)} subdomains in {output_file}")
            else:
                self.logger.error(f"Subfinder failed: {result.stderr}")
                # Fallback to built-in enumeration
                with open(output_file, 'w') as f:
                    f.write(f"www.{domain}\nmail.{domain}\napi.{domain}\n")
        except Exception as e:
            self.logger.error(f"Error running subfinder: {e}")
            # Fallback to simple enumeration
            with open(output_file, 'w') as f:
                f.write(f"www.{domain}\nmail.{domain}\napi.{domain}\n")

    def enumerate_second_level(self, input_file, output_file):
        """Enumerate second level subdomains"""
        if not os.path.exists(input_file):
            return
            
        with open(input_file, 'r') as f:
            subdomains = [line.strip() for line in f if line.strip()]
        
        with open(output_file, 'w') as f:
            for sub in subdomains:
                # TODO: Implement actual second-level enumeration
                f.write(f"dev.{sub}\n")
                f.write(f"test.{sub}\n")
        self.logger.info(f"Second-level subdomains saved to {output_file}")

    def get_waybackurls(self, domain, output_file):
        """Get historical URLs from Wayback Machine"""
        # TODO: Implement actual waybackurls integration
        with open(output_file, 'w') as f:
            f.write(f"old.{domain}\n")
            f.write(f"archive.{domain}\n")
        self.logger.info(f"Wayback URLs saved to {output_file}")

    def consolidate_subdomains(self, input_files, output_file):
        """Combine and deduplicate subdomains from multiple sources"""
        unique_subs = set()
        
        for file in input_files:
            if os.path.exists(file):
                with open(file, 'r') as f:
                    unique_subs.update(line.strip() for line in f if line.strip())
        
        with open(output_file, 'w') as f:
            f.write('\n'.join(sorted(unique_subs)))
        self.logger.info(f"Consolidated {len(unique_subs)} subdomains to {output_file}")

    def check_live_hosts(self, input_file, output_file):
        """Check which subdomains are alive using parallel requests"""
        if not os.path.exists(input_file):
            return
            
        with open(input_file, 'r') as f:
            subdomains = [line.strip() for line in f if line.strip()]
        
        def check_host(host):
            try:
                if not host.startswith(('http://', 'https://')):
                    host = f"http://{host}"
                resp = requests.get(host, timeout=5, allow_redirects=False)
                if resp.status_code < 400:
                    return host
            except:
                return None
            return None
        
        alive_hosts = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            for host in executor.map(check_host, subdomains):
                if host:
                    alive_hosts.append(host)
        
        with open(output_file, 'w') as f:
            f.write('\n'.join(alive_hosts))
        self.logger.info(f"Found {len(alive_hosts)} live hosts saved to {output_file}")

    def scan_ports(self, input_file, output_file):
        """Scan for open ports using python-nmap"""
        if not os.path.exists(input_file):
            return
            
        with open(input_file, 'r') as f:
            hosts = [line.strip() for line in f if line.strip()]

        nm = nmap.PortScanner()
        port_results = []
        common_ports = '21,22,23,25,53,80,110,135,139,443,445,1433,1521,3306,3389,5432,8080,8443'

        for host in hosts:
            try:
                # Clean host URL if needed
                if host.startswith(('http://', 'https://')):
                    from urllib.parse import urlparse
                    host = urlparse(host).netloc

                self.logger.info(f"Scanning {host}...")
                nm.scan(host, arguments=f'-sS -sV -p{common_ports} -T4')
                
                if host in nm.all_hosts():
                    open_ports = []
                    for proto in nm[host].all_protocols():
                        ports = nm[host][proto].keys()
                        for port in ports:
                            try:
                                state = nm[host][proto][port]['state']
                                if state == 'open':
                                    service = nm[host][proto][port]['name']
                                    version = nm[host][proto][port].get('version', '')
                                    product = nm[host][proto][port].get('product', '')
                                    port_info = f"{port}/{proto} {service}"
                                    if product:
                                        port_info += f" ({product}"
                                        if version:
                                            port_info += f" {version}"
                                        port_info += ")"
                                    open_ports.append(port_info)
                            except:
                                continue

                    if open_ports:
                        port_results.append(f"{host}:")
                        for port in sorted(open_ports, key=lambda x: int(x.split('/')[0])):
                            port_results.append(f"  {port}")
                    else:
                        port_results.append(f"{host}: No open ports found")
                else:
                    port_results.append(f"{host}: Host seems down")
                    
            except Exception as e:
                port_results.append(f"{host}: Error - {str(e)}")

        with open(output_file, 'w') as f:
            f.write('\n'.join(port_results))
        self.logger.info(f"Port scan results saved to {output_file}")

    async def is_wordpress(self, url):
        """Check if a site is running WordPress"""
        wp_paths = ['/wp-login.php', '/wp-admin/', '/wp-content/']
        async with aiohttp.ClientSession() as session:
            for path in wp_paths:
                try:
                    async with session.get(urljoin(url, path), ssl=False) as response:
                        if response.status == 200 or response.status == 403:
                            return True
                except:
                    continue
            return False

    def detect_tech(self, input_file, output_file):
        """Detect web technologies using Wappalyzer"""
        if not os.path.exists(input_file):
            return
            
        try:
            from wappalyzer import Wappalyzer, WebPage
        except ImportError:
            self.logger.error("python-Wappalyzer not installed - pip install python-Wappalyzer")
            return
            
        with open(input_file, 'r') as f:
            hosts = [line.strip() for line in f if line.strip()]
        
        wappalyzer = Wappalyzer.latest()
        tech_results = []

        for host in hosts:
            try:
                if not host.startswith(('http://', 'https://')):
                    host = f"http://{host}"

                # Try both http and https
                for protocol in ['https', 'http']:
                    try:
                        test_url = f"{protocol}://{host}" if not host.startswith(('http://', 'https://')) else host
                        response = requests.get(
                            test_url,
                            timeout=self.timeout,
                            headers={'User-Agent': 'Mozilla/5.0'},
                            verify=False
                        )
                        
                        webpage = WebPage.new_from_response(response)
                        technologies = wappalyzer.analyze(webpage)

                        if technologies:
                            tech_results.append(f"{test_url}:")
                            for tech_category, tech_list in technologies.items():
                                if tech_list:
                                    tech_results.append(f"  {tech_category}:")
                                    for tech in tech_list:
                                        tech_results.append(f"    - {tech}")
                            break
                        
                    except requests.RequestException:
                        continue
                
                if not any(line.startswith(host) for line in tech_results):
                    tech_results.append(f"{host}: No technologies detected or site unreachable")

            except Exception as e:
                tech_results.append(f"{host}: Error - {str(e)}")

        with open(output_file, 'w') as f:
            f.write('\n'.join(tech_results))
        self.logger.info(f"Technology detection results saved to {output_file}")

    def crawl_and_screenshot(self, input_file, output_dir, timeout=10):
        """Take screenshots using Selenium with improved error handling"""
        if not os.path.exists(input_file):
            self.logger.error(f"Input file not found: {input_file}")
            return
            
        os.makedirs(output_dir, exist_ok=True)
        
        with open(input_file, 'r') as f:
            hosts = [line.strip() for line in f if line.strip()]
        
        try:
            from selenium.common.exceptions import WebDriverException
            
            # Set up Chrome driver with automatic ChromeDriver management
            driver = self.setup_chromedriver()
            if not driver:
                self.logger.error("Failed to initialize ChromeDriver")
                return
                
            driver.set_page_load_timeout(timeout)
            
            for host in hosts:
                try:
                    if not host.startswith(('http://', 'https://')):
                        host = f"http://{host}"
                    
                    self.logger.info(f"Capturing screenshot of {host}")
                    driver.get(host)
                    
                    # Get page dimensions and set window size
                    total_width = driver.execute_script("return document.body.scrollWidth")
                    total_height = driver.execute_script("return document.body.scrollHeight")
                    driver.set_window_size(total_width, total_height)
                    
                    # Save screenshot
                    screenshot_file = os.path.join(
                        output_dir, 
                        f"{host.replace('://', '_').replace('/', '_')}.png"
                    )
                    driver.save_screenshot(screenshot_file)
                    
                except WebDriverException as e:
                    self.logger.error(f"Failed to capture {host}: {str(e)}")
                    continue
                    
            driver.quit()
            self.logger.info(f"Screenshots saved to {output_dir}")
            
        except Exception as e:
            self.logger.error(f"Error during screenshot capture: {e}")

    def generate_payloads(self, output_dir):
        """Generate custom payloads for each vulnerability type"""
        os.makedirs(output_dir, exist_ok=True)
        vuln_types = [
            'xss', 'sqli', 'rce', 'lfi', 'ssrf',
            'xxe', 'csrf', 'idor', 'ssti', 'oauth'
        ]
        for vuln in vuln_types:
            payload_file = os.path.join(output_dir, f"{vuln}_payloads.txt")
            with open(payload_file, 'w') as f:
                for i in range(1, 101):
                    f.write(f"{vuln.upper()}_PAYLOAD_{i}: ")
                    if vuln == 'xss':
                        f.write(f'<script>alert("XSS_{i}")</script>\n')
                    elif vuln == 'sqli':
                        f.write(f"' OR {i}=1--\n")
                    elif vuln == 'rce':
                        f.write(f'; echo "RCE_{i}"\n')
            self.logger.info(f"Generated 100 {vuln.upper()} payloads in {payload_file}")

    def run_tool(self, command, tool_name, timeout=None):
        """Run an external security tool and handle its output"""
        try:
            self.logger.info(f"Running {tool_name}...")
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                shell=True,
                timeout=timeout or self.timeout * 2
            )
            if result.returncode == 0:
                return result.stdout
            else:
                self.logger.error(f"{tool_name} failed: {result.stderr}")
                return None
        except subprocess.TimeoutExpired:
            self.logger.error(f"{tool_name} timed out after {timeout or self.timeout * 2} seconds")
            return None
        except Exception as e:
            self.logger.error(f"Error running {tool_name}: {str(e)}")
            return None

    def scan_with_nmap_advanced(self, target, output_file):
        """Advanced port scanning and service enumeration with Nmap"""
        nmap_output = self.run_tool(
            f"nmap -sS -sV -sC -A -p- -T4 --version-all -oN {output_file} {target}",
            "Nmap Advanced",
            timeout=900  # 15 minutes timeout for full scan
        )
        return nmap_output is not None

    def scan_with_dirb(self, target, output_file, custom_wordlist=None):
        """Directory bruteforcing with dirb"""
        # Get the wordlist
        wordlist = self.get_wordlist('directories', custom_wordlist)
        
        # Create a temporary wordlist file
        temp_wordlist = os.path.join(os.path.dirname(output_file), 'temp_dirb_wordlist.txt')
        try:
            with open(temp_wordlist, 'w') as f:
                f.write('\n'.join(wordlist))
            
            # Run dirb with the wordlist
            dirb_output = self.run_tool(
                f"dirb {target} {temp_wordlist} -o {output_file} -w",
                "Dirb"
            )
            return dirb_output is not None
        finally:
            # Clean up temporary wordlist
            if os.path.exists(temp_wordlist):
                os.remove(temp_wordlist)

    def scan_with_nuclei(self, target, output_file):
        """Vulnerability scanning with Nuclei"""
        nuclei_output = self.run_tool(
            f"nuclei -u {target} -o {output_file} -severity critical,high,medium,low -silent",
            "Nuclei"
        )
        return nuclei_output is not None

    def scan_with_whatweb(self, target, output_file):
        """Web technology detection with WhatWeb"""
        whatweb_output = self.run_tool(
            f"whatweb -a 4 {target} --log-file={output_file}",
            "WhatWeb"
        )
        return whatweb_output is not None

    def scan_with_droopescan(self, target, output_file):
        """CMS vulnerability scanning with droopescan"""
        droope_output = self.run_tool(
            f"droopescan scan drupal -u {target} -o {output_file}",
            "Droopescan"
        )
        joom_output = self.run_tool(
            f"droopescan scan joomla -u {target} -o {output_file}",
            "Droopescan"
        )
        return droope_output is not None or joom_output is not None

    def scan_with_skipfish(self, target, output_dir):
        """Web application security assessment with Skipfish"""
        skipfish_output = self.run_tool(
            f"skipfish -o {output_dir} {target}",
            "Skipfish",
            timeout=1800  # 30 minutes timeout
        )
        return skipfish_output is not None

    def scan_with_arachni(self, target, output_file):
        """Web application security scanning with Arachni"""
        arachni_output = self.run_tool(
            f"arachni {target} --output-only-positives --report-save-path={output_file}",
            "Arachni",
            timeout=3600  # 1 hour timeout
        )
        return arachni_output is not None

    def scan_with_nikto(self, target, output_file):
        """Scan target with Nikto web server scanner"""
        nikto_output = self.run_tool(
            f"nikto -h {target} -o {output_file} -Format txt",
            "Nikto"
        )
        return nikto_output is not None

    def scan_with_sqlmap(self, target, output_dir):
        """Scan for SQL injection vulnerabilities using SQLMap"""
        sqlmap_output = self.run_tool(
            f"sqlmap -u {target} --batch --random-agent --output-dir={output_dir}",
            "SQLMap"
        )
        return sqlmap_output is not None

    def scan_with_wpscan(self, target, output_file):
        """Scan WordPress sites using WPScan"""
        wpscan_output = self.run_tool(
            f"wpscan --url {target} --output {output_file} --format cli",
            "WPScan"
        )
        return wpscan_output is not None

    def scan_with_gobuster(self, target, output_file, custom_wordlist=None):
        """Directory enumeration using GoBuster"""
        # Get the wordlist
        wordlist = self.get_wordlist('directories', custom_wordlist)
        
        # Create a temporary wordlist file
        temp_wordlist = os.path.join(os.path.dirname(output_file), 'temp_wordlist.txt')
        try:
            with open(temp_wordlist, 'w') as f:
                f.write('\n'.join(wordlist))
            
            # Run GoBuster with the wordlist
            gobuster_output = self.run_tool(
                f"gobuster dir -u {target} -w {temp_wordlist} -o {output_file} -q",
                "GoBuster"
            )
            return gobuster_output is not None
        finally:
            # Clean up temporary wordlist
            if os.path.exists(temp_wordlist):
                os.remove(temp_wordlist)

    def scan_with_sslyze(self, target, output_file):
        """SSL/TLS security scanner using SSLyze"""
        sslyze_output = self.run_tool(
            f"sslyze --regular {target} --json_out {output_file}",
            "SSLyze"
        )
        return sslyze_output is not None

    def scan_vulnerabilities(self, alive_file, output_file, payloads_dir):
        """Comprehensive vulnerability scanning using multiple tools"""
        if not os.path.exists(alive_file):
            return

        with open(alive_file, 'r') as f:
            hosts = [line.strip() for line in f if line.strip()]

        vuln_results = []
        
        # Create directories for tool outputs
        tools_dir = os.path.join(os.path.dirname(output_file), "tool_results")
        os.makedirs(tools_dir, exist_ok=True)
        
        # Common wordlist for directory scanning
        wordlist = os.path.join(tools_dir, "common.txt")
        with open(wordlist, 'w') as f:
            f.write('\n'.join([
                'admin', 'wp-admin', 'login', 'wp-login.php', 'administrator',
                'backup', 'db', 'sql', 'dev', 'test', 'api', 'v1', 'v2',
                'config', 'settings', 'upload', 'uploads', 'files', 'images',
                'php.ini', '.env', '.git', 'robots.txt', 'sitemap.xml'
            ]))

        async def scan_host(host):
            if not host.startswith(('http://', 'https://')):
                host = f'http://{host}'
                
            host_dir = os.path.join(tools_dir, urlparse(host).netloc)
            os.makedirs(host_dir, exist_ok=True)
            
            # Run external tool scans
            tool_results = []
            
            # Nikto scan
            nikto_file = os.path.join(host_dir, "nikto_results.txt")
            if self.scan_with_nikto(host, nikto_file):
                with open(nikto_file) as f:
                    tool_results.extend(
                        f"{host}: [Nikto] {line.strip()}" 
                        for line in f if "+" in line
                    )
            
            # SQLMap scan
            sqlmap_dir = os.path.join(host_dir, "sqlmap")
            if self.scan_with_sqlmap(host, sqlmap_dir):
                for root, _, files in os.walk(sqlmap_dir):
                    for file in files:
                        if file.endswith('.txt'):
                            with open(os.path.join(root, file)) as f:
                                content = f.read()
                                if 'Parameter:' in content:
                                    tool_results.append(
                                        f"{host}: [SQLMap] SQL injection found - {file}"
                                    )
            
            # WordPress scan
            if await self.is_wordpress(host):
                wp_file = os.path.join(host_dir, "wpscan_results.txt")
                if self.scan_with_wpscan(host, wp_file):
                    with open(wp_file) as f:
                        tool_results.extend(
                            f"{host}: [WPScan] {line.strip()}"
                            for line in f if '[+]' in line or '[!]' in line
                        )
            
            # Directory enumeration
            dir_file = os.path.join(host_dir, "gobuster_results.txt")
            if self.scan_with_gobuster(host, wordlist, dir_file):
                with open(dir_file) as f:
                    interesting_files = []
                    for line in f:
                        if any(word in line.lower() for word in ['admin', 'config', 'backup', 'db', '.git']):
                            interesting_files.append(line.strip())
                    if interesting_files:
                        tool_results.append(
                            f"{host}: [GoBuster] Found sensitive files/directories:\n    " +
                            "\n    ".join(interesting_files)
                        )
            
            # SSL/TLS scan
            if host.startswith('https://'):
                ssl_file = os.path.join(host_dir, "sslyze_results.json")
                if self.scan_with_sslyze(urlparse(host).netloc, ssl_file):
                    with open(ssl_file) as f:
                        ssl_data = json.load(f)
                        for finding in ssl_data.get('server_scan_results', []):
                            if finding.get('scan_status') == 'ERROR':
                                tool_results.append(
                                    f"{host}: [SSLyze] {finding.get('scan_result', {}).get('error_message')}"
                                )
            
            # Add tool results to main findings
            vuln_results.extend(tool_results)

            self.logger.info(f"Scanning {host}...")
            host_vulns = []

            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
                    # SQLi detection
                    sqli_payloads = ["'", "1' OR '1'='1", "1; SELECT 1", "' UNION SELECT NULL--"]
                    for payload in sqli_payloads:
                        test_url = urljoin(host, f'?id={payload}')
                        async with session.get(test_url, ssl=False) as response:
                            text = await response.text()
                            if any(err in text.lower() for err in ['sql', 'mysql', 'oracle', 'syntax']):
                                host_vulns.append(f"{host}: [HIGH] Potential SQL Injection - Parameter: id")
                                break

                    # XSS detection
                    xss_payloads = ['"><script>alert(1)</script>', "'><img src=x onerror=alert(1)>"]
                    for payload in xss_payloads:
                        test_url = urljoin(host, f'?q={payload}')
                        async with session.get(test_url, ssl=False) as response:
                            text = await response.text()
                            if payload in text:
                                host_vulns.append(f"{host}: [HIGH] Potential XSS - Parameter: q")
                                break

                    # Directory traversal
                    lfi_payloads = ['../../../etc/passwd', '..%2f..%2f..%2fetc%2fpasswd']
                    for payload in lfi_payloads:
                        test_url = urljoin(host, f'?file={payload}')
                        async with session.get(test_url, ssl=False) as response:
                            text = await response.text()
                            if 'root:' in text or 'nobody:' in text:
                                host_vulns.append(f"{host}: [HIGH] Potential Directory Traversal - Parameter: file")
                                break

                    # SSRF detection
                    ssrf_payloads = ['http://localhost', 'http://127.0.0.1']
                    for payload in ssrf_payloads:
                        test_url = urljoin(host, f'?url={payload}')
                        async with session.get(test_url, ssl=False) as response:
                            if response.status == 200:
                                host_vulns.append(f"{host}: [MEDIUM] Potential SSRF - Parameter: url")
                                break

                    # Check security headers
                    async with session.get(host, ssl=False) as response:
                        headers = response.headers
                        if 'X-Frame-Options' not in headers:
                            host_vulns.append(f"{host}: [LOW] Missing X-Frame-Options header")
                        if 'X-Content-Type-Options' not in headers:
                            host_vulns.append(f"{host}: [LOW] Missing X-Content-Type-Options header")
                        if 'Content-Security-Policy' not in headers:
                            host_vulns.append(f"{host}: [LOW] Missing Content-Security-Policy header")

                    # Check for information disclosure using wordlist
                    sensitive_files = self.get_wordlist('common_files', 
                        self.config.get('wordlists', {}).get('sensitive_files'))
                    for path in [f"/{file}" for file in sensitive_files]:
                        test_url = urljoin(host, path)
                        try:
                            async with session.get(test_url, ssl=False) as response:
                                if response.status == 200:
                                    host_vulns.append(f"{host}: [MEDIUM] Potential Information Disclosure - {path}")
                        except:
                            continue

            except aiohttp.ClientError as e:
                host_vulns.append(f"{host}: Error during scan - {str(e)}")
            except Exception as e:
                host_vulns.append(f"{host}: Unexpected error - {str(e)}")

            return host_vulns

        # Run scans asynchronously
        async def run_scans():
            tasks = []
            for host in hosts:
                tasks.append(scan_host(host))
            results = await asyncio.gather(*tasks)
            for host_results in results:
                vuln_results.extend(host_results)

        # Create event loop and run scans
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(run_scans())
        except Exception as e:
            self.logger.error(f"Error during vulnerability scanning: {e}")
            vuln_results.append(f"Error during vulnerability scanning: {str(e)}")
        finally:
            loop.close()

        # Process custom payloads
        if os.path.exists(payloads_dir):
            self.logger.info("Running custom payload scans...")
            for payload_file in os.listdir(payloads_dir):
                if not payload_file.endswith('.txt'):
                    continue

                vuln_type = payload_file.split('_')[0].upper()
                with open(os.path.join(payloads_dir, payload_file), 'r') as f:
                    payloads = [line.strip() for line in f if line.strip()]

                async def test_custom_payloads():
                    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
                        for host in hosts:
                            if not host.startswith(('http://', 'https://')):
                                host = f'http://{host}'

                            for payload in payloads:
                                try:
                                    test_url = urljoin(host, f'?test={payload}')
                                    async with session.get(test_url, ssl=False) as response:
                                        text = await response.text()
                                        if payload in text:
                                            vuln_results.append(f"{host}: [HIGH] Potential {vuln_type} vulnerability detected")
                                            break
                                except:
                                    continue

                try:
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    loop.run_until_complete(test_custom_payloads())
                except Exception as e:
                    self.logger.error(f"Error testing custom payloads: {e}")
                finally:
                    loop.close()

        with open(output_file, 'w') as f:
            f.write('\n'.join(vuln_results))
        self.logger.info(f"Found {len(vuln_results)} potential vulnerabilities in {output_file}")

    def quick_scan(self, target):
        """
        Perform a quick security assessment of the target.
        Includes basic port scanning, common vulnerability checks,
        and fast subdomain enumeration.
        """
        session_dir = os.path.join(
            self.config.get('output_dir', 'results'),
            f"quick_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )
        os.makedirs(session_dir, exist_ok=True)

        self.logger.info(f"Starting quick scan of {target}")
        results = []

        # Basic port scan using nmap
        self.logger.info("Running quick port scan...")
        ports_file = os.path.join(session_dir, "ports.txt")
        common_ports = [80, 443, 8080, 8443, 21, 22, 23, 25, 53]  # Common web and service ports
        
        try:
            nm = nmap.PortScanner()
            nm.scan(target, arguments='-sV -T4 -p80,443,8080,8443')
            
            with open(ports_file, 'w') as f:
                for host in nm.all_hosts():
                    f.write(f"Host: {host}\n")
                    for proto in nm[host].all_protocols():
                        f.write(f"Protocol: {proto}\n")
                        ports = nm[host][proto].keys()
                        for port in ports:
                            state = nm[host][proto][port]['state']
                            if state == 'open':
                                service = nm[host][proto][port]['name']
                                f.write(f"Port: {port}/{proto} ({service})\n")
            results.append(("Port Scan", ports_file))

            # Quick web checks
            has_web = False
            for host in nm.all_hosts():
                tcp_ports = nm[host].get('tcp', {})
                if 80 in tcp_ports or 443 in tcp_ports:
                    has_web = True
                    break
                    
            if has_web:
                web_file = os.path.join(session_dir, "web_scan.txt")
        except nmap.PortScannerError as e:
            self.logger.error(f"Nmap scan failed: {str(e)}")
            # Fall back to basic socket scanning
            with open(ports_file, 'w') as f:
                f.write(f"Host: {target}\n")
                for port in common_ports:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(1)
                        result = sock.connect_ex((target, port))
                        if result == 0:
                            f.write(f"Port {port}: Open\n")
                        sock.close()
                    except:
                        continue
            results.append(("Port Scan (Basic)", ports_file))
            # Always check for web servers in fallback mode
            web_file = os.path.join(session_dir, "web_scan.txt")
            with open(web_file, 'w') as f:
                # Check common vulnerable paths
                paths = ['/admin', '/wp-admin', '/phpinfo.php', '/test.php', '/.git']
                for path in paths:
                    try:
                        url = f"http://{target}{path}"
                        resp = requests.get(url, timeout=5, verify=False)
                        if resp.status_code != 404:
                            f.write(f"Found: {url} (Status: {resp.status_code})\n")
                    except:
                        continue
            results.append(("Web Scan", web_file))

        # Basic DNS enumeration
        dns_file = os.path.join(session_dir, "dns.txt")
        with open(dns_file, 'w') as f:
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT']
            resolver = dns.resolver.Resolver()
            for record in record_types:
                try:
                    answers = resolver.resolve(target, record)
                    f.write(f"\n{record} Records:\n")
                    for rdata in answers:
                        f.write(f"  {str(rdata)}\n")
                except:
                    continue
        results.append(("DNS Records", dns_file))

        # Generate quick report
        report_file = os.path.join(session_dir, "quick_report.txt")
        with open(report_file, 'w') as f:
            f.write("CodesHacks Quick Scan Report\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Target: {target}\n")
            f.write(f"Scan Date: {datetime.now()}\n\n")

            for section, result_file in results:
                f.write(f"\n{section}\n")
                f.write("-" * len(section) + "\n")
                if os.path.exists(result_file):
                    with open(result_file) as rf:
                        f.write(rf.read())
                f.write("\n")

        self.logger.info(f"Quick scan completed. Report saved to: {report_file}")
        return report_file

    def full_scan(self, target):
        """
        Perform a comprehensive security assessment using all available tools.
        Includes deep scanning, vulnerability assessment, and extensive enumeration.
        """
        session_dir = os.path.join(
            self.config.get('output_dir', 'results'),
            f"full_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )
        os.makedirs(session_dir, exist_ok=True)
        
        self.logger.info(f"Starting full scan of {target}")
        
        # Phase 1: Passive Reconnaissance
        self.logger.info("Phase 1: Passive Reconnaissance")
        subs_file = self.passive_recon(target, session_dir)
        
        # Phase 2: Active Scanning
        self.logger.info("Phase 2: Active Scanning")
        alive_file = self.active_scan(target, subs_file, session_dir)
        
        # Phase 3: Advanced Port Scanning
        self.logger.info("Phase 3: Advanced Port Scanning")
        nmap_file = os.path.join(session_dir, "nmap_advanced.txt")
        self.scan_with_nmap_advanced(target, nmap_file)
        
        # Phase 4: Web Application Analysis
        self.logger.info("Phase 4: Web Application Analysis")
        web_dir = os.path.join(session_dir, "web")
        os.makedirs(web_dir, exist_ok=True)
        
        # Run web scanners
        self.scan_with_nikto(target, os.path.join(web_dir, "nikto.txt"))
        self.scan_with_dirb(target, os.path.join(web_dir, "dirb.txt"))
        self.scan_with_whatweb(target, os.path.join(web_dir, "whatweb.txt"))
        
        # CMS Detection and Scanning
        if asyncio.run(self.is_wordpress(f"http://{target}")):
            self.scan_with_wpscan(target, os.path.join(web_dir, "wpscan.txt"))
        self.scan_with_droopescan(target, os.path.join(web_dir, "droopescan.txt"))
        
        # Phase 5: Advanced Web Security Assessment
        self.logger.info("Phase 5: Advanced Web Security Assessment")
        self.scan_with_skipfish(target, os.path.join(web_dir, "skipfish"))
        self.scan_with_arachni(target, os.path.join(web_dir, "arachni.txt"))
        
        # Phase 6: Vulnerability Scanning
        self.logger.info("Phase 6: Vulnerability Scanning")
        nuclei_file = os.path.join(session_dir, "nuclei.txt")
        self.scan_with_nuclei(target, nuclei_file)
        
        # Phase 7: Targeted Testing
        self.logger.info("Phase 7: Targeted Testing")
        vuln_dir = os.path.join(session_dir, "vulnerabilities")
        os.makedirs(vuln_dir, exist_ok=True)
        self.scan_vulnerabilities(alive_file, os.path.join(vuln_dir, "vulnerabilities.txt"), None)
        
        # Generate comprehensive report
        report_file = os.path.join(session_dir, "full_report.txt")
        self.generate_comprehensive_report(target, session_dir, report_file)
        
        self.logger.info(f"Full scan completed. Report saved to: {report_file}")
        return report_file

    def analyze_web_server(self, domain, output_file):
        """Analyze web server with enhanced domain checking"""
        self.logger.info(f"Starting web server analysis for {domain}")
        
        with open(output_file, 'w') as f:
            f.write(f"Web Server Analysis for {domain}\n")
            f.write("=" * 50 + "\n\n")
            
            # Common subdomains to test
            subdomains = ['www', 'api', 'mail', 'blog']
            domains_to_test = [domain] + [f"{sub}.{domain}" for sub in subdomains]
            
            for test_domain in domains_to_test:
                f.write(f"\nAnalyzing domain: {test_domain}\n")
                f.write("-" * (len(test_domain) + 20) + "\n")
                
                for protocol in ['https', 'http']:
                    url = f"{protocol}://{test_domain}"
                    f.write(f"\nTesting {url}:\n")
                    
                    try:
                        response = requests.get(
                            url,
                            timeout=10,
                            verify=False,
                            headers={
                                'User-Agent': 'Mozilla/5.0',
                                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
                            },
                            allow_redirects=True
                        )
                        
                        # Handle redirects
                        if response.history:
                            f.write("\nRedirect chain:\n")
                            for r in response.history:
                                f.write(f"  {r.url} ({r.status_code})\n")
                            f.write(f"  Final: {response.url}\n")
                        
                        f.write(f"\nStatus: {response.status_code}\n")
                        
                        # Server headers
                        if response.headers:
                            f.write("\nServer Headers:\n")
                            for header, value in response.headers.items():
                                f.write(f"  {header}: {value}\n")
                        
                        # Content analysis
                        content_type = response.headers.get('content-type', '').lower()
                        if 'text/html' in content_type:
                            f.write("\nAnalyzing HTML content:\n")
                            try:
                                soup = BeautifulSoup(response.text, 'html.parser')
                                
                                # Title
                                if soup.title:
                                    f.write(f"Title: {soup.title.string.strip()}\n")
                                
                                # Meta tags
                                meta_tags = []
                                for meta in soup.find_all('meta'):
                                    if meta.get('name') and meta.get('content'):
                                        meta_tags.append(f"{meta['name']}: {meta['content']}")
                                
                                if meta_tags:
                                    f.write("\nMeta Tags:\n")
                                    for tag in meta_tags:
                                        f.write(f"  {tag}\n")
                                
                                # Technology detection
                                techs = []
                                
                                # From headers
                                for header in ['Server', 'X-Powered-By', 'X-AspNet-Version']:
                                    if header in response.headers:
                                        techs.append(f"{header}: {response.headers[header]}")
                                
                                # From HTML
                                for script in soup.find_all('script', src=True):
                                    if script.get('src'):
                                        techs.append(f"Script: {script['src']}")
                                
                                if techs:
                                    f.write("\nDetected Technologies:\n")
                                    for tech in techs:
                                        f.write(f"  {tech}\n")
                                else:
                                    f.write("\nNo specific technologies detected\n")
                                    
                            except Exception as e:
                                f.write(f"\nError parsing HTML: {str(e)}\n")
                        else:
                            f.write(f"\nNon-HTML response (Content-Type: {content_type})\n")
                            
                    except requests.exceptions.SSLError as e:
                        f.write(f"SSL Error: {str(e)}\n")
                    except requests.exceptions.Timeout:
                        f.write("Error: Connection timed out\n")
                    except requests.exceptions.ConnectionError:
                        f.write("Error: Could not connect to server\n")
                    except Exception as e:
                        f.write(f"Error: {str(e)}\n")
                    
                    f.write("\n" + "-" * 50 + "\n")
    
    def custom_scan(self, target, tools):
        """
        Perform a custom scan using specified tools.
        
        Args:
            target: Target domain or IP
            tools: List of tool names to use
        """
        print("\nStarting custom scan:")
        print(f"Target: {target}")
        print(f"Tools: {tools}")
        print(f"Results directory: {self.results_dir}")
        print(f"Session directory: {self.session_dir}")
        
        self.logger.info(f"Starting custom scan of {target} with tools: {', '.join(tools)}")
        
        # Parse tools list if string
        if isinstance(tools, str):
            tools = [t.strip() for t in tools.split(',')]
        
        # Clean and validate target
        target = target.replace('http://', '').replace('https://', '').strip('/')
        print(f"Cleaned target: {target}")
        
        try:
            import socket
            ip = socket.gethostbyname(target)
            print(f"Resolved {target} to {ip}")
        except socket.gaierror as e:
            self.logger.error(f"Could not resolve hostname: {target}")
            print(f"DNS resolution error: {e}")
            return
            
        self.logger.info(f"Target validated: {target}")
        results = []

        # Create scan directories
        scan_dir = os.path.join(self.session_dir, "custom_scan")
        print(f"Creating scan directory: {scan_dir}")
        try:
            os.makedirs(scan_dir, exist_ok=True)
            print("Directory created successfully")
        except Exception as e:
            print(f"Error creating directory: {e}")
            raise
            
        self.logger.info(f"Created scan directory: {scan_dir}")

        # Basic DNS enumeration
        if any(t in ['dns', 'passive', 'recon'] for t in tools):
            dns_file = os.path.join(scan_dir, "dns.txt")
            self.logger.info("Performing DNS enumeration...")
            
            with open(dns_file, 'w') as f:
                f.write(f"DNS Enumeration Results for {target}\n")
                f.write("=" * 50 + "\n\n")
                
                # Common DNS record types
                record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
                resolver = dns.resolver.Resolver()
                resolver.timeout = self.timeout
                resolver.lifetime = self.timeout
                
                for record in record_types:
                    try:
                        f.write(f"\n{record} Records:\n")
                        f.write("-" * (len(record) + 9) + "\n")
                        answers = resolver.resolve(target, record)
                        for rdata in answers:
                            f.write(f"{str(rdata)}\n")
                    except Exception as e:
                        f.write(f"Failed to get {record} records: {str(e)}\n")
                
            results.append(("DNS", dns_file))

        # Basic port scanning
        if any(t in ['ports', 'tcp', 'scan'] for t in tools):
            ports_file = os.path.join(scan_dir, "ports.txt")
            self.logger.info("Performing port scan...")
            
            with open(ports_file, 'w') as f:
                f.write(f"Port Scan Results for {target}\n")
                f.write("=" * 50 + "\n\n")
                
                # Common web ports to check
                common_ports = [80, 443, 8080, 8443]
                
                import socket
                socket.setdefaulttimeout(2)
                
                for port in common_ports:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        result = sock.connect_ex((target, port))
                        if result == 0:
                            f.write(f"Port {port}: Open\n")
                            try:
                                service = socket.getservbyport(port)
                                f.write(f"  Service: {service}\n")
                            except:
                                pass
                        sock.close()
                    except Exception as e:
                        f.write(f"Error scanning port {port}: {str(e)}\n")
                
            results.append(("Ports", ports_file))

        # Web server analysis
        if any(t in ['web', 'http', 'whatweb'] for t in tools):
            web_file = os.path.join(scan_dir, "web.txt")
            self.logger.info("Analyzing web server...")
            
            with open(web_file, 'w') as f:
                f.write(f"Web Server Analysis for {target}\n")
                f.write("=" * 50 + "\n\n")
                
                # Try both http and https
                for protocol in ['http', 'https']:
                    url = f"{protocol}://{target}"
                    try:
                        response = requests.get(
                            url, 
                            timeout=self.timeout,
                            verify=False,
                            headers={'User-Agent': 'Mozilla/5.0'}
                        )
                        
                        if response.status_code != 200:
                            f.write(f"\n{protocol.upper()} ({response.status_code}) - Server returned non-200 status code\n")
                            f.write("-" * 20 + "\n")
                            f.write("Headers:\n")
                            for header, value in response.headers.items():
                                f.write(f"  {header}: {value}\n")
                        else:
                            f.write(f"\n{protocol.upper()} ({response.status_code}):\n")
                            f.write("-" * 20 + "\n")
                            
                            # Server information
                            f.write("Server Headers:\n")
                            for header, value in response.headers.items():
                                f.write(f"  {header}: {value}\n")
                            
                            # Parse HTML
                            soup = BeautifulSoup(response.text, 'html.parser')
                            
                            # Title
                            if soup.title:
                                f.write(f"\nPage Title: {soup.title.string}\n")
                            
                            # Meta tags
                            meta_tags = soup.find_all('meta')
                            if meta_tags:
                                f.write("\nMeta Tags:\n")
                                for meta in meta_tags:
                                    if meta.get('name'):
                                        f.write(f"  {meta.get('name')}: {meta.get('content')}\n")
                            
                            # Technologies
                            tech_found = False
                            f.write("\nPotential Technologies:\n")
                            if 'X-Powered-By' in response.headers:
                                f.write(f"  {response.headers['X-Powered-By']}\n")
                                tech_found = True
                            for script in soup.find_all('script'):
                                if script.get('src'):
                                    f.write(f"  Script: {script['src']}\n")
                                    tech_found = True
                            if not tech_found:
                                f.write("  No technologies detected\n")
                                
                    except requests.RequestException as e:
                        f.write(f"\n{protocol.upper()} Error: {str(e)}\n")
            
            results.append(("Web", web_file))

        # Generate summary report
        report_file = os.path.join(scan_dir, "summary_report.txt")
        with open(report_file, 'w') as f:
            f.write(f"Scan Summary for {target}\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Scan Date: {datetime.now()}\n")
            f.write(f"Tools Used: {', '.join(tools)}\n\n")
            
            for tool, result_file in results:
                f.write(f"\n{tool} Results\n")
                f.write("-" * (len(tool) + 8) + "\n")
                if os.path.exists(result_file):
                    with open(result_file) as rf:
                        f.write(rf.read())
                f.write("\n" + "=" * 50 + "\n")

        self.logger.info(f"Custom scan completed. Report saved to: {report_file}")
        return report_file

    def generate_custom_report(self, target, results, report_file):
        """Generate a report for custom scan results"""
        with open(report_file, 'w') as f:
            f.write("CodesHacks Custom Scan Report\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Target: {target}\n")
            f.write(f"Scan Date: {datetime.now()}\n")
            f.write(f"Tools Used: {len(results)}\n\n")

            for tool, result_file in results:
                f.write(f"\n{tool} Results\n")
                f.write("-" * (len(tool) + 8) + "\n")
                if os.path.exists(result_file):
                    if os.path.isfile(result_file):
                        with open(result_file) as rf:
                            f.write(rf.read())
                    else:
                        f.write(f"Results directory: {result_file}\n")
                f.write("\n")

    def generate_comprehensive_report(self, target, scan_dir, report_file):
        """Generate a comprehensive report from full scan results"""
        with open(report_file, 'w') as f:
            f.write("CodesHacks Comprehensive Security Assessment Report\n")
            f.write("=" * 60 + "\n\n")
            f.write(f"Target: {target}\n")
            f.write(f"Scan Date: {datetime.now()}\n\n")

            # Organize findings by severity
            findings = {
                'CRITICAL': [], 'HIGH': [], 'MEDIUM': [], 'LOW': [], 
                'INFO': [], 'UNKNOWN': []
            }
            
            # Process all result files
            for root, _, files in os.walk(scan_dir):
                for file in files:
                    if file.endswith(('.txt', '.json')):
                        file_path = os.path.join(root, file)
                        tool_name = os.path.basename(root) or os.path.splitext(file)[0]
                        
                        with open(file_path) as rf:
                            content = rf.read()
                            
                            # Extract findings and categorize by severity
                            for line in content.splitlines():
                                if any(sev in line for sev in findings.keys()):
                                    for sev in findings.keys():
                                        if sev in line:
                                            findings[sev].append(f"[{tool_name}] {line}")
                                            break
            
            # Write Executive Summary
            f.write("Executive Summary\n")
            f.write("-" * 30 + "\n")
            total_findings = sum(len(v) for v in findings.values())
            f.write(f"Total Findings: {total_findings}\n\n")
            
            f.write("Findings by Severity:\n")
            for sev, items in findings.items():
                if items:
                    f.write(f"- {sev}: {len(items)}\n")
            f.write("\n")
            
            # Write Detailed Findings
            f.write("Detailed Findings\n")
            f.write("-" * 30 + "\n\n")
            
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNKNOWN']:
                if findings[severity]:
                    f.write(f"\n{severity} Severity Findings:\n")
                    f.write("=" * (len(severity) + 18) + "\n")
                    for finding in findings[severity]:
                        f.write(f"{finding}\n")
                    f.write("\n")

    def generate_report(self, input_file, output_file):
        """Generate a detailed report of findings"""
        if not os.path.exists(input_file):
            return

        with open(input_file, 'r') as f:
            findings = [line.strip() for line in f if line.strip()]

        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0}
        type_counts = {'XSS': 0, 'SQLi': 0, 'RCE': 0, 'Other': 0}

        # Count findings by severity and type
        for finding in findings:
            for sev in severity_counts:
                if f'[{sev}]' in finding.upper():
                    severity_counts[sev] += 1
                    break

            if 'XSS' in finding.upper():
                type_counts['XSS'] += 1
            elif 'SQLI' in finding.upper():
                type_counts['SQLi'] += 1
            elif 'RCE' in finding.upper():
                type_counts['RCE'] += 1
            else:
                type_counts['Other'] += 1

        # Generate report
        with open(output_file, 'w') as f:
            f.write("CodesHacks Vulnerability Report\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Report Generated: {datetime.now()}\n\n")

            f.write("Executive Summary\n")
            f.write("-" * 30 + "\n")
            f.write(f"Total vulnerabilities found: {len(findings)}\n\n")

            f.write("Severity Distribution:\n")
            for sev, count in severity_counts.items():
                f.write(f"- {sev}: {count}\n")
            f.write("\n")

            f.write("Vulnerability Types:\n")
            for vtype, count in type_counts.items():
                f.write(f"- {vtype}: {count}\n")
            f.write("\n")

            f.write("Detailed Findings\n")
            f.write("-" * 30 + "\n")
            for finding in findings:
                f.write(f"{finding}\n")

        self.logger.info(f"Report generated: {output_file}")
