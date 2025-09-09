#!/usr/bin/env python3
"""
CodesHacks - Advanced Web Reconnaissance & Vulnerability Scanning Tool

A comprehensive web security assessment framework that combines passive reconnaissance,
active scanning, and vulnerability detection capabilities.

Author: Raj Shrivastav
"""

from __future__ import annotations

import json
import logging
import os
import socket
import sys
import traceback
from configparser import ConfigParser
from datetime import datetime
from typing import Dict, List, Optional, Union
from modules.core.man_command import handle_man_command
from modules.utils.logging import print_status

try:
    from docopt import docopt, DocoptExit
    from selenium.webdriver.chrome.options import Options
except ImportError as e:
    print(f"Required dependency not found: {e}")
    print("Please install required packages: pip install -r requirements.txt")
    sys.exit(1)

# Custom exceptions
class CodesHacksError(Exception):
    """Base exception class for CodesHacks errors."""
    pass

class ConfigError(CodesHacksError):
    """Raised when configuration errors occur."""
    pass

class BrowserSetupError(CodesHacksError):
    """Raised when browser setup fails."""
    pass

class APIError(CodesHacksError):
    """Raised when API related errors occur."""
    pass

class ScanError(CodesHacksError):
    """Raised when scanning operations fail."""
    pass

# Enable debug mode globally
sys.excepthook = lambda exctype, value, tb: print(f"{exctype.__name__}: {value}\n{''.join(traceback.format_tb(tb))}")

sys.excepthook = lambda exctype, value, tb: print(f"{exctype.__name__}: {value}\n{''.join(traceback.format_tb(tb))}")

print(f"Python version: {sys.version}")
print(f"Python executable: {sys.executable}")
print(f"Current working directory: {os.getcwd()}")

print("Starting imports...")
# Add current directory to Python path to find local modules
import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    import socket
    import logging
    import argparse
    import configparser
    from docopt import docopt, DocoptExit
    from datetime import datetime
    from selenium.webdriver.chrome.options import Options
    print("Basic imports successful. Importing local modules...")
    
    # Import local modules
    import modules.scanner as scanner
    from modules.tools.unified_tools import UnifiedTools
    # Get classes from modules
    Scanner = scanner.Scanner
    print("All imports successful!")
except ImportError as e:
    print(f"Error importing module: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Tool Information and Constants
TOOL_INFO: Dict[str, str] = {
    'name': 'CodesHacks',
    'version': '1.1.0',
    'author': 'Raj Shrivastav',
    'description': 'Advanced Web Reconnaissance & Vulnerability Scanning Tool',
    'repository': 'https://github.com/RAJSHRIVASTAV397/CodesHacks',
    'license': 'MIT',
    'python_version': f"{sys.version_info.major}.{sys.version_info.minor}"
}

# Default Configuration
DEFAULT_CONFIG: Dict[str, Union[str, int, bool]] = {
    'threads': 10,
    'timeout': 10,
    'rate_limit': 50,
    'debug': False,
    'output_dir': 'codeshacks_results',
    'scan_modes': ['passive', 'active', 'vuln', 'full'],
    'user_agent': f"CodesHacks/{TOOL_INFO['version']} (+{TOOL_INFO['repository']})"
}

# Banner with ANSI color codes
BANNER = '''
██████╗ ██████╗ ██████╗ ███████╗██╗  ██╗ █████╗  ██████╗██╗  ██╗███████╗
██╔════╝██╔═══██╗██╔══██╗██╔════╝██║  ██║██╔══██╗██╔════╝██║ ██╔╝██╔════╝
██║     ██║   ██║██║  ██║█████╗  ███████║███████║██║     █████╔╝ ███████╗
██║     ██║   ██║██║  ██║██╔══╝  ██╔══██║██╔══██║██║     ██╔═██╗ ╚════██║
╚██████╗╚██████╔╝██████╔╝███████╗██║  ██║██║  ██║╚██████╗██║  ██╗███████║
 ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝
                    Advanced Reconnaissance Framework v0.1
                           Author: Raj Shrivastav
         Repository: https://github.com/RAJSHRIVASTAV397/CodesHacks
'''

class CodesHacks:
    """Main class for the CodesHacks security assessment tool.
    
    This class handles initialization, configuration, and execution of all scanning
    features. It manages the tool's lifecycle including setup, scanning, and reporting.
    
    Attributes:
        version (str): Current version of the tool
        output_dir (str): Base directory for all scan outputs
        timestamp (str): Timestamp for the current scan session
        api_keys (dict): API keys for various external services
        config_file (str): Path to the configuration file
        session_dir (str): Directory for current scan session
        logger (logging.Logger): Logger instance for the tool
    """
    
    def __init__(self):
        """Initialize CodesHacks with default configuration.
        
        Sets up the basic tool configuration, logging, and required directories.
        Loads configuration from file and environment variables.
        
        Raises:
            OSError: If unable to create required directories
            ConfigError: If configuration loading fails
            ImportError: If required dependencies are missing
        """
        self.print_banner()
        print("Initializing CodesHacks...")
        
        try:
            # Parse command line arguments first
            self.args = self.parse_arguments()
            
            # Basic setup
            self.version = TOOL_INFO['version']
            self.output_dir = self.args.get('output', DEFAULT_CONFIG['output_dir'])
            self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.api_keys: Dict[str, str] = {}
            self.config_file = 'codeshacks.ini'
            self.session_dir = None
            self._setup_complete = False
            
            print("Setting up tool options...")
            # Initialize tools configuration
            self.tool_options = {
                'api_keys': self.api_keys,
                'threads': self.args.get('threads', DEFAULT_CONFIG['threads']),
                'timeout': self.args.get('timeout', DEFAULT_CONFIG['timeout']),
                'rate_limit': self.args.get('rate_limit', DEFAULT_CONFIG['rate_limit'])
            }

            # Setup components
            print("Setting up logging...")
            self.setup_logging()
            print("Loading config...")
            self.load_config()
            print("Loading API keys...")
            self.load_api_keys()
            print("Setting up browser...")
            self.setup_browser()
            
            print("Initializing scanner and tools...")
            # Initialize scanner and unified tools
            self.scanner = Scanner(self.tool_options, self.logger)
            self.tools = UnifiedTools(self.logger, self.output_dir, self.tool_options)
            print("CodesHacks initialized successfully!")
        except Exception as e:
            print(f"Error in initialization: {e}")
            import traceback
            traceback.print_exc()
            raise

    def setup_logging(self):
        """Configure comprehensive logging with file and console handlers"""
        # Create output directory structure
        self.session_dir = os.path.join(self.output_dir, f'scan_{self.timestamp}')
        self.logs_dir = os.path.join(self.session_dir, 'logs')
        self.results_dir = os.path.join(self.session_dir, 'results')
        self.evidence_dir = os.path.join(self.session_dir, 'evidence')
        
        # Create all directories
        for directory in [self.logs_dir, self.results_dir, self.evidence_dir]:
            os.makedirs(directory, exist_ok=True)
        
        # Setup main log file
        main_log = os.path.join(self.logs_dir, 'codeshacks.log')
        debug_log = os.path.join(self.logs_dir, 'debug.log')
        error_log = os.path.join(self.logs_dir, 'error.log')
        
        self.logger = logging.getLogger('CodesHacks')
        self.logger.setLevel(logging.DEBUG)
        
        # Main log handler (INFO level)
        main_handler = logging.FileHandler(main_log)
        main_handler.setLevel(logging.INFO)
        main_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        main_handler.setFormatter(main_formatter)
        
        # Debug log handler (DEBUG level)
        debug_handler = logging.FileHandler(debug_log)
        debug_handler.setLevel(logging.DEBUG)
        debug_formatter = logging.Formatter('%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s')
        debug_handler.setFormatter(debug_formatter)
        
        # Error log handler (ERROR level)
        error_handler = logging.FileHandler(error_log)
        error_handler.setLevel(logging.ERROR)
        error_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s\n%(exc_info)s')
        error_handler.setFormatter(error_formatter)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_formatter = logging.Formatter('%(levelname)s: %(message)s')
        console_handler.setFormatter(console_formatter)
        
        # Add all handlers
        self.logger.addHandler(main_handler)
        self.logger.addHandler(debug_handler)
        self.logger.addHandler(error_handler)
        self.logger.addHandler(console_handler)
        
        # Log initial session information
        self.logger.info(f"Starting new scan session: {self.timestamp}")
        self.logger.info(f"Output directory: {self.session_dir}")
        self.logger.debug("Logging system initialized")

    def load_config(self):
        """Load configuration from INI file"""
        config = configparser.ConfigParser()
        if os.path.exists(self.config_file):
            config.read(self.config_file)
            
            # Load settings
            if 'SETTINGS' in config:
                self.output_dir = config['SETTINGS'].get('output_dir', self.output_dir)
                self.threads = config['SETTINGS'].getint('threads', 10)
                self.timeout = config['SETTINGS'].getint('timeout', 10)
                self.rate_limit = config['SETTINGS'].getint('rate_limit', 50)
                self.debug = config['SETTINGS'].getboolean('debug', False)
                
            # Load scan options
            if 'SCAN_OPTIONS' in config:
                self.top_ports = config['SCAN_OPTIONS'].getint('top_ports', 100)
                self.screenshot_timeout = config['SCAN_OPTIONS'].getint('screenshot_timeout', 10)
                self.crawl_depth = config['SCAN_OPTIONS'].getint('crawl_depth', 3)
                self.passive_only = config['SCAN_OPTIONS'].getboolean('passive_only', False)
                self.active_only = config['SCAN_OPTIONS'].getboolean('active_only', False)
                self.vuln_only = config['SCAN_OPTIONS'].getboolean('vuln_only', False)
        else:
            self.logger.warning(f"Configuration file {self.config_file} not found, using defaults")
            # Set default values
            self.threads = 10
            self.timeout = 10
            self.rate_limit = 50
            self.debug = False
            self.top_ports = 100
            self.screenshot_timeout = 10
            self.crawl_depth = 3
            self.passive_only = False
            self.active_only = False
            self.vuln_only = False

    def load_api_keys(self):
        """Load API keys from configuration file and environment variables"""
        apis = ['shodan', 'censys', 'virustotal', 'securitytrails', 'alienvault']

        # First try environment variables
        for api in apis:
            env_key = os.getenv(f"{api.upper()}_API_KEY")
            if env_key:
                self.api_keys[api] = env_key
                self.logger.debug(f"Loaded {api} API key from environment")

        # Then try config file
        config = configparser.ConfigParser()
        if os.path.exists(self.config_file):
            config.read(self.config_file)
            if 'API_KEYS' in config:
                for api in apis:
                    if not self.api_keys.get(api) and config['API_KEYS'].get(api):
                        self.api_keys[api] = config['API_KEYS'][api]
                        self.logger.debug(f"Loaded {api} API key from config file")

        # Prompt for missing keys if running interactively and --no-api not set
        if sys.stdin.isatty() and not self.args.get('no_api'):
            updated = False
            for api in apis:
                if not self.api_keys.get(api):
                    user_key = input(f"[?] Enter your {api.title()} API key (leave blank to skip): ").strip()
                    if user_key:
                        save = input(f"[?] Save this {api.title()} API key to config file? (y/n): ").strip().lower()
                        self.api_keys[api] = user_key
                        if save == 'y':
                            if 'API_KEYS' not in config:
                                config['API_KEYS'] = {}
                            config['API_KEYS'][api] = user_key
                            updated = True

            if updated:
                try:
                    with open(self.config_file, 'w') as f:
                        config.write(f)
                    self.logger.info("API keys saved to config file")
                except Exception as e:
                    self.logger.error(f"Failed to save API keys to config file: {str(e)}")

        # Log API key status
        for api in apis:
            status = 'Set' if self.api_keys.get(api) else 'Not Set'
            self.logger.debug(f"{api.title()} API key: {status}")

    def setup_browser(self) -> None:
        """Configure Chrome browser options for web scanning and screenshots.
        
        Sets up Chrome in headless mode with security and performance optimizations.
        Configures window size, GPU, sandbox settings, and certificate handling.
        
        Raises:
            BrowserSetupError: If browser configuration fails
        """
        try:
            self.chrome_options = Options()
            
            # Security settings
            self.chrome_options.add_argument("--headless")
            self.chrome_options.add_argument("--no-sandbox")
            self.chrome_options.add_argument("--disable-dev-shm-usage")
            
            # Performance settings
            self.chrome_options.add_argument("--disable-gpu")
            self.chrome_options.add_argument("--disable-software-rasterizer")
            self.chrome_options.add_argument("--disable-extensions")
            
            # Browser behavior
            self.chrome_options.add_argument("--window-size=1920,1080")
            self.chrome_options.add_argument("--ignore-certificate-errors")
            self.chrome_options.add_argument(f"--user-agent={DEFAULT_CONFIG['user_agent']}")
            
            # Memory management
            self.chrome_options.add_argument("--disable-dev-shm-usage")
            self.chrome_options.add_argument("--disable-application-cache")
            
            self.logger.debug("Browser options configured successfully")
            
        except Exception as e:
            error_msg = f"Failed to setup browser options: {str(e)}"
            self.logger.error(error_msg)
            self.chrome_options = None
            raise BrowserSetupError(error_msg)

    def create_output_dir(self) -> str:
        """Create a structured output directory for the current scan session.
        
        Creates a timestamped directory with subdirectories for different types
        of scan outputs, evidence, and reports. Directory structure follows:
        
        session_dir/
        ├── results/
        │   ├── recon/      - Reconnaissance findings
        │   ├── scan/       - Scan results
        │   └── vulns/      - Vulnerability reports
        ├── evidence/
        │   ├── screenshots/  - Web page screenshots
        │   ├── payloads/    - Used attack payloads
        │   └── responses/   - Server responses
        ├── logs/
        │   ├── debug/      - Debug logs
        │   ├── error/      - Error logs
        │   └── requests/   - Request logs
        └── reports/
            ├── json/       - JSON format reports
            ├── html/       - HTML format reports
            └── txt/        - Text format reports
        
        Returns:
            str: Path to created session directory
            
        Raises:
            OSError: If directory creation fails
        """
        try:
            # Create session directory with timestamp
            session_dir = os.path.join(self.output_dir, self.timestamp)
            
            # Directory structure definition
            dirs = {
                'results': ['recon', 'scan', 'vulns'],
                'evidence': ['screenshots', 'payloads', 'responses'],
                'logs': ['debug', 'error', 'requests'],
                'reports': ['json', 'html', 'txt']
            }
            
            # Create all directories
            for main_dir, subdirs in dirs.items():
                for subdir in subdirs:
                    dir_path = os.path.join(session_dir, main_dir, subdir)
                    os.makedirs(dir_path, exist_ok=True)
                    self.logger.debug(f"Created directory: {dir_path}")
            
            return session_dir
            
        except OSError as e:
            error_msg = f"Failed to create output directory structure: {str(e)}"
            self.logger.error(error_msg)
            raise OSError(error_msg)
        
    def generate_scan_summary(self, scan_type, results):
        """Generate a comprehensive scan summary and save to multiple formats"""
        summary = {
            'scan_info': {
                'timestamp': self.timestamp,
                'tool_version': self.version,
                'scan_type': scan_type,
                'duration': str(datetime.now() - datetime.strptime(self.timestamp, "%Y%m%d_%H%M%S"))
            },
            'target_info': {
                'domain': self.target_domain,
                'scope': self.scope if hasattr(self, 'scope') else None,
                'excluded': self.excluded if hasattr(self, 'excluded') else None
            },
            'scan_results': results
        }
        
        # Save as JSON
        json_path = os.path.join(self.session_dir, 'reports', 'json', f'summary_{self.timestamp}.json')
        with open(json_path, 'w') as f:
            json.dump(summary, f, indent=4)
        
        # Generate HTML report
        html_path = os.path.join(self.session_dir, 'reports', 'html', f'report_{self.timestamp}.html')
        self.generate_html_report(summary, html_path)
        
        # Generate text summary
        txt_path = os.path.join(self.session_dir, 'reports', 'txt', f'summary_{self.timestamp}.txt')
        with open(txt_path, 'w') as f:
            f.write(f"CodesHacks Scan Summary\n")
            f.write(f"{'='*50}\n\n")
            f.write(f"Scan Information:\n")
            f.write(f"  Timestamp: {summary['scan_info']['timestamp']}\n")
            f.write(f"  Tool Version: {summary['scan_info']['tool_version']}\n")
            f.write(f"  Scan Type: {summary['scan_info']['scan_type']}\n")
            f.write(f"  Duration: {summary['scan_info']['duration']}\n\n")
            f.write(f"Target Information:\n")
            f.write(f"  Domain: {summary['target_info']['domain']}\n")
            if summary['target_info']['scope']:
                f.write(f"  Scope: {summary['target_info']['scope']}\n")
            if summary['target_info']['excluded']:
                f.write(f"  Excluded: {summary['target_info']['excluded']}\n\n")
            f.write(f"Results Summary:\n")
            for category, items in summary['scan_results'].items():
                f.write(f"\n{category}:\n")
                if isinstance(items, list):
                    for item in items:
                        f.write(f"  - {item}\n")
                elif isinstance(items, dict):
                    for key, value in items.items():
                        f.write(f"  {key}: {value}\n")
                else:
                    f.write(f"  {items}\n")
        
        self.logger.info(f"Scan summary generated:")
        self.logger.info(f"  - JSON: {json_path}")
        self.logger.info(f"  - HTML: {html_path}")
        self.logger.info(f"  - Text: {txt_path}")
        
    def generate_html_report(self, summary, output_path):
        """Generate a formatted HTML report from scan summary"""
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>CodesHacks Scan Report</title>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; }
                .container { max-width: 1200px; margin: 0 auto; }
                .header { background: #2c3e50; color: white; padding: 20px; margin-bottom: 20px; }
                .section { background: #f9f9f9; padding: 20px; margin-bottom: 20px; border-radius: 5px; }
                .results { background: white; padding: 15px; margin-top: 10px; border-radius: 3px; }
                h1, h2 { margin: 0; }
                table { width: 100%; border-collapse: collapse; margin-top: 10px; }
                th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
                th { background-color: #f5f5f5; }
                .severity-high { color: #e74c3c; }
                .severity-medium { color: #f39c12; }
                .severity-low { color: #3498db; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>CodesHacks Scan Report</h1>
                    <p>Generated: {timestamp}</p>
                </div>
                
                <div class="section">
                    <h2>Scan Information</h2>
                    <table>
                        <tr><th>Tool Version</th><td>{version}</td></tr>
                        <tr><th>Scan Type</th><td>{scan_type}</td></tr>
                        <tr><th>Duration</th><td>{duration}</td></tr>
                    </table>
                </div>
                
                <div class="section">
                    <h2>Target Information</h2>
                    <table>
                        <tr><th>Domain</th><td>{domain}</td></tr>
                        <tr><th>Scope</th><td>{scope}</td></tr>
                        <tr><th>Excluded</th><td>{excluded}</td></tr>
                    </table>
                </div>
                
                <div class="section">
                    <h2>Scan Results</h2>
                    {results_html}
                </div>
            </div>
        </body>
        </html>
        """
        
        # Generate results HTML
        results_html = ""
        for category, items in summary['scan_results'].items():
            results_html += f"<div class='results'><h3>{category}</h3>"
            if isinstance(items, list):
                results_html += "<ul>"
                for item in items:
                    severity_class = ""
                    if "HIGH" in str(item): severity_class = "severity-high"
                    elif "MEDIUM" in str(item): severity_class = "severity-medium"
                    elif "LOW" in str(item): severity_class = "severity-low"
                    results_html += f"<li class='{severity_class}'>{item}</li>"
                results_html += "</ul>"
            elif isinstance(items, dict):
                results_html += "<table>"
                for key, value in items.items():
                    results_html += f"<tr><th>{key}</th><td>{value}</td></tr>"
                results_html += "</table>"
            else:
                results_html += f"<p>{items}</p>"
            results_html += "</div>"
            
        # Fill template
        html_content = html_template.format(
            timestamp=summary['scan_info']['timestamp'],
            version=summary['scan_info']['tool_version'],
            scan_type=summary['scan_info']['scan_type'],
            duration=summary['scan_info']['duration'],
            domain=summary['target_info']['domain'],
            scope=summary['target_info']['scope'] or "Not specified",
            excluded=summary['target_info']['excluded'] or "None",
            results_html=results_html
        )
        
        # Write HTML file
        with open(output_path, 'w') as f:
            f.write(html_content)

    def print_banner(self) -> None:
        """Print the tool banner with version and author information."""
        print(BANNER)

    def show_help(self) -> str:
        """Display help menu and usage information.
        
        Returns:
            str: The complete help text with usage information and examples.
        """
        return """CodesHacks - Advanced Web Security Assessment Tool

Usage:
    codeshacks.py -d DOMAIN [-p PROJECT] [-o DIR] [-m MODE] [options]
    codeshacks.py (-h | --help)
    codeshacks.py --version
    codeshacks.py --list-tools        List all available security tools
    codeshacks.py --tool-help TOOL    Show help for specific tool

Arguments:
    -d, --domain DOMAIN    Target domain or IP to scan
    -p, --project NAME    Project name for output organization
    -o, --output DIR      Output directory [default: ./codeshacks_results]
    -m, --mode MODE       Scan mode [default: full] (passive|active|vuln|full|quick|stealth)

Tool Categories:
    Core Security Tools:
        --nuclei           Run Nuclei vulnerability scanner
        --nmap            Run Nmap port scanner
        --subfinder       Run Subfinder for subdomain discovery
        --httpx           Run httpx for HTTP probing
        --feroxbuster     Run Feroxbuster for directory enumeration
        --sqlmap          Run SQLMap for SQL injection testing
        --nikto           Run Nikto web scanner
        --gobuster        Run Gobuster for directory/file brute forcing
        --ffuf            Run FFUF web fuzzer
        --wpscan          Run WPScan for WordPress scanning
        --dalfox          Run Dalfox XSS scanner

    Advanced Security Tools:
        Web Application:
            --burpsuite    Run Burp Suite automated scan
            --zap          Run OWASP ZAP scan
            --arachni      Run Arachni web scanner
        
        Network Security:
            --metasploit   Run Metasploit scan/exploit
            --wireshark    Capture and analyze network traffic
            --hydra        Run Hydra password cracker
        
        Forensics & RE:
            --volatility   Run memory analysis
            --autopsy      Run digital forensics
            --ghidra       Run binary analysis
            --radare2      Run reverse engineering analysis
        
        Cloud Security:
            --prowler      Run AWS security assessment
            --cloudsploit  Run cloud infrastructure scan
            --trivy        Run container security scan
        
        Mobile Security:
            --mobsf        Run mobile app security scan
            --apktool      Android APK analysis
            --frida        Dynamic instrumentation

Tool Options:
    --tool-config FILE      Load tool-specific configuration
    --tool-output DIR      Custom output directory for tool results
    --tool-threads NUM     Tool-specific thread count
    --tool-timeout SECS    Tool-specific timeout
    
    Nuclei Options:
        --nuclei-severity LEV    Severity filter (critical,high,medium,low)
        --nuclei-tags TAGS       Specific tags to run
        --nuclei-templates DIR   Custom templates directory
        
    Container Scan Options:
        --trivy-severity LEV     Severity filter for vulnerabilities
        --trivy-ignore-unfixed   Skip unfixed vulnerabilities
        
    Web Scan Options:
        --burp-config FILE       Burp Suite configuration file
        --zap-context FILE      ZAP context file
        --spider-depth NUM      Maximum crawl depth
        
    Mobile Scan Options:
        --mobsf-type TYPE       Scan type (static/dynamic)
        --mobsf-format FMT      Report format (json/pdf)

General Options:
    -h, --help                Show this help message
    --version                 Show version information
    -v, --verbose            Enable verbose output
    -q, --quiet              Suppress console output
    --debug                  Enable debug logging
    --no-update             Skip tool updates

Scan Configuration:
    --threads NUM            Number of concurrent threads [default: 10]
    --timeout SECS          Request timeout in seconds [default: 10]
    --rate-limit NUM        Maximum requests per second [default: 50]
    --delay MS             Delay between requests [default: 100]
    --retry NUM             Number of retry attempts [default: 3]
    --scope SCOPE          Define scan scope (e.g., *.domain.com)
    --exclude PAT          Exclude patterns (comma-separated)
    --include PAT          Include only specific patterns
    --ports PORTS         Custom port ranges to scan
    
Output Options:
    --json                  Generate JSON report
    --html                  Generate HTML report
    --txt                   Generate text report
    --no-color              Disable colored output

Scanning Features:
    --dns                   Enable DNS enumeration
    --ports                Enable port scanning
    --web                  Enable web scanning
    --vuln                 Enable vulnerability scanning
    --fuzz                 Enable fuzzing
    --brute                Enable brute force attacks
    --ssl                  Enable SSL/TLS scanning
    
Advanced Options:
    --custom-dns SERVERS   Use custom DNS servers (comma-separated)
    --proxy URL           Use proxy (e.g., http://127.0.0.1:8080)
    --cookies FILE        Load cookies from file
    --user-agent STRING   Custom User-Agent string

Examples:
    1. Basic scan with default options:
       codeshacks.py -d example.com

    2. Full scan with custom threads and rate limit:
       codeshacks.py -d example.com --threads 20 --rate-limit 100

    3. Passive reconnaissance only:
       codeshacks.py -d example.com -m passive

    4. Vulnerability scan with custom ports:
       codeshacks.py -d example.com -m vuln --ports 80,443,8080-8090

    5. Stealth mode scan:
       codeshacks.py -d example.com -m stealth --delay 2000

Tool-Specific Examples:
    1. Run Nuclei with custom templates:
       codeshacks.py -d example.com --nuclei --nuclei-templates /path/to/templates
       
    2. Container security scan:
       codeshacks.py --trivy nginx:latest --trivy-severity HIGH,CRITICAL
       
    3. Mobile app analysis:
       codeshacks.py --mobsf app.apk --mobsf-type static --mobsf-format pdf
       
    4. Web application scan with Burp Suite:
       codeshacks.py -d example.com --burpsuite --burp-config config.json
       
    5. Combined tools scan:
       codeshacks.py -d example.com --nuclei --subfinder --httpx
       
    6. Cloud infrastructure assessment:
       codeshacks.py --prowler --profile aws-profile-name
       
    7. Memory forensics:
       codeshacks.py --volatility memory.dump --profile Win10x64

Tool Configuration:
    1. Configure tools using config file:
       codeshacks.py --tool-config tools_config.json
       
    2. Update tool settings:
       codeshacks.py --configure-tool nuclei --set severity=high,critical
       
    3. List installed tools:
       codeshacks.py --list-tools
       
    4. Show tool-specific help:
       codeshacks.py --tool-help nuclei

Environment Variables:
    CODESHACKS_CONFIG    Path to configuration file
    CODESHACKS_TOOLS     Path to custom tools directory
    CODESHACKS_DEBUG     Enable debug mode
    CODESHACKS_NO_COLOR  Disable colored output

API Keys (can be set in codeshacks.ini or environment):
    SHODAN_API_KEY         Shodan API key
    CENSYS_API_KEY         Censys API key
    VIRUSTOTAL_API_KEY     VirusTotal API key
    SECURITYTRAILS_KEY     SecurityTrails API key
    ALIENVAULT_KEY         AlienVault API key

Notes:
    - Results are saved in the output directory under a timestamped folder
    - Each tool's output is organized in its own subdirectory
    - Use --debug for detailed logging during execution
    - Rate limiting is recommended to avoid detection
    - Some tools require root/administrator privileges
    - Tools are automatically installed if missing

For more information and updates, visit:
https://github.com/RAJSHRIVASTAV397/CodesHacks"""

    def parse_arguments(self) -> dict:
        """Parse and validate command line arguments."""
        parser = argparse.ArgumentParser(
            description=TOOL_INFO['description'],
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=self.show_help(),
            usage=argparse.SUPPRESS
        )

        # Main Arguments
        main_group = parser.add_argument_group('Main Arguments')
        main_group.add_argument('-d', '--domain',
            help='Target domain or IP address to scan')
        main_group.add_argument('-m', '--mode', 
            choices=['passive', 'active', 'vuln', 'full', 'quick', 'stealth'],
            default='full', 
            help='Scan mode')
        main_group.add_argument('-o', '--output',
            default=DEFAULT_CONFIG['output_dir'],
            help='Output directory for scan results')
        main_group.add_argument('-p', '--project',
            help='Project name for organizing results')

        # Tool Selection
        tools_group = parser.add_argument_group('Tool Selection')
        tools_group.add_argument('--list-tools', action='store_true',
            help='List all available security tools')
        tools_group.add_argument('--tool-help',
            help='Show help for specific tool')
        
        # Core Tools
        core_tools = parser.add_argument_group('Core Security Tools')
        core_tools.add_argument('--nuclei', action='store_true',
            help='Run Nuclei vulnerability scanner')
        core_tools.add_argument('--nmap', action='store_true',
            help='Run Nmap port scanner')
        core_tools.add_argument('--subfinder', action='store_true',
            help='Run Subfinder for subdomain discovery')
        core_tools.add_argument('--httpx', action='store_true',
            help='Run httpx for HTTP probing')
        core_tools.add_argument('--feroxbuster', action='store_true',
            help='Run Feroxbuster for directory enumeration')
        core_tools.add_argument('--sqlmap', action='store_true',
            help='Run SQLMap for SQL injection testing')

        # Advanced Tools
        adv_tools = parser.add_argument_group('Advanced Security Tools')
        adv_tools.add_argument('--burpsuite', action='store_true',
            help='Run Burp Suite automated scan')
        adv_tools.add_argument('--zap', action='store_true',
            help='Run OWASP ZAP scan')
        adv_tools.add_argument('--metasploit', action='store_true',
            help='Run Metasploit scan/exploit')
        adv_tools.add_argument('--mobsf', action='store_true',
            help='Run mobile app security scan')
        adv_tools.add_argument('--trivy', action='store_true',
            help='Run container security scan')
        
        # Tool Configuration
        tool_config = parser.add_argument_group('Tool Configuration')
        tool_config.add_argument('--tool-config',
            help='Load tool-specific configuration file')
        tool_config.add_argument('--nuclei-severity',
            help='Nuclei severity filter (critical,high,medium,low)')
        tool_config.add_argument('--nuclei-templates',
            help='Custom Nuclei templates directory')
        tool_config.add_argument('--trivy-severity',
            help='Trivy severity filter')
        tool_config.add_argument('--mobsf-type',
            choices=['static', 'dynamic'],
            help='MobSF analysis type')
        
        # Scan Configuration
        scan_config = parser.add_argument_group('Scan Configuration')
        scan_config.add_argument('--threads', type=int,
            default=DEFAULT_CONFIG['threads'],
            help='Number of concurrent threads')
        scan_config.add_argument('--timeout', type=int,
            default=DEFAULT_CONFIG['timeout'],
            help='Request timeout in seconds')
        scan_config.add_argument('--rate-limit', type=int,
            default=DEFAULT_CONFIG['rate_limit'],
            help='Maximum requests per second')
        scan_config.add_argument('--delay', type=int,
            help='Delay between requests (ms)')
        scan_config.add_argument('--scope',
            help='Define scan scope (e.g., *.domain.com)')
        scan_config.add_argument('--exclude',
            help='Exclude patterns (comma-separated)')
        scan_config.add_argument('--ports',
            help='Custom port ranges to scan')

        # API Configuration
        api_config = parser.add_argument_group('API Configuration')
        api_config.add_argument('--no-api', action='store_true',
            help='Skip API key prompts')
        api_config.add_argument('--shodan-key',
            help='Shodan API key')
        api_config.add_argument('--censys-key',
            help='Censys API key')
        api_config.add_argument('--virustotal-key',
            help='VirusTotal API key')
        
        # Output Options
        output_group = parser.add_argument_group('Output Options')
        output_group.add_argument('--debug', action='store_true',
            help='Enable debug mode')
        output_group.add_argument('-v', '--verbose', action='store_true',
            help='Enable verbose output')
        output_group.add_argument('-q', '--quiet', action='store_true',
            help='Suppress console output')
        output_group.add_argument('--no-color', action='store_true',
            help='Disable colored output')

        args = parser.parse_args()

        # If list-tools is specified, show tools and exit
        if args.list_tools:
            self._list_available_tools()
            sys.exit(0)

        # If tool-help is specified, show tool help and exit
        if args.tool_help:
            self._show_tool_help(args.tool_help)
            sys.exit(0)

        # Convert args to dict
        args_dict = vars(args)
        
        # Set default values from DEFAULT_CONFIG if not specified
        for key, value in DEFAULT_CONFIG.items():
            if key not in args_dict or args_dict[key] is None:
                args_dict[key] = value

        return args_dict

    def _list_available_tools(self):
        """Display list of all available security tools."""
        print("\nAvailable Security Tools:")
        print("\nCore Security Tools:")
        print("  - nuclei: Advanced vulnerability scanner")
        print("  - nmap: Network port scanner")
        print("  - subfinder: Subdomain discovery tool")
        print("  - httpx: HTTP probe toolkit")
        print("  - feroxbuster: Directory enumeration")
        print("  - sqlmap: SQL injection testing")
        
        print("\nWeb Application Tools:")
        print("  - burpsuite: Web application security testing")
        print("  - zap: OWASP ZAP security scanner")
        print("  - nikto: Web server scanner")
        
        print("\nNetwork Security Tools:")
        print("  - metasploit: Penetration testing framework")
        print("  - wireshark: Network protocol analyzer")
        print("  - hydra: Password cracking")
        
        print("\nCloud & Container Security:")
        print("  - trivy: Container vulnerability scanner")
        print("  - prowler: AWS security assessment")
        print("  - cloudsploit: Cloud security posture")
        
        print("\nMobile Security Tools:")
        print("  - mobsf: Mobile app security testing")
        print("  - apktool: Android APK analysis")
        print("  - frida: Dynamic instrumentation")

    def _show_tool_help(self, tool_name: str):
        """Display help for specific tool."""
        tool_help = {
            'nuclei': """Nuclei Vulnerability Scanner
Usage: --nuclei [options]
Options:
  --nuclei-severity      Severity filter (critical,high,medium,low)
  --nuclei-templates    Custom templates directory
  --nuclei-tags        Specific tags to run""",
            
            'trivy': """Trivy Container Scanner
Usage: --trivy [options]
Options:
  --trivy-severity     Severity filter for vulnerabilities
  --trivy-ignore-unfixed Skip unfixed vulnerabilities""",
            
            'mobsf': """MobSF Mobile Security Framework
Usage: --mobsf [options]
Options:
  --mobsf-type        Scan type (static/dynamic)
  --mobsf-format     Report format (json/pdf)"""
        }
        
        if tool_name in tool_help:
            print(f"\n{tool_help[tool_name]}")
        else:
            print(f"\nNo detailed help available for {tool_name}")
            print("Use --list-tools to see all available tools")
        
        parser = argparse.ArgumentParser(
            description='CodesHacks - Advanced Web Reconnaissance & Vulnerability Scanner',
            add_help=False
        )

        # Target options
        target_group = parser.add_argument_group('Target Options')
        target_group.add_argument('-d', '--domain', required=True,
            help='Target domain or IP address to scan')
        target_group.add_argument('--scope',
            help='Define scan scope using wildcards (e.g., *.domain.com)')
        target_group.add_argument('--exclude',
            help='Exclude specific subdomains or patterns from scan')
        target_group.add_argument('--include',
            help='Include only specific subdomains in scan')
        target_group.add_argument('--ports',
            help='Custom port ranges (default: top 1000)')

        # Scan modes
        mode_group = parser.add_argument_group('Scan Modes')
        mode_group.add_argument('--full', action='store_true', help='Full assessment')
        mode_group.add_argument('--passive', action='store_true', help='Passive recon only')
        mode_group.add_argument('--active', action='store_true', help='Active scanning only')
        mode_group.add_argument('--vuln', action='store_true', help='Vulnerability scanning only')
        mode_group.add_argument('--quick', action='store_true', help='Quick scan')
        mode_group.add_argument('--stealth', action='store_true', help='Stealth scan')

        # Tool configuration
        tool_group = parser.add_argument_group('Tool Configuration')
        tool_group.add_argument('--httpx-options', help='Additional httpx options')
        tool_group.add_argument('--katana-depth', type=int, default=10, help='Crawl depth')
        tool_group.add_argument('--kiterunner-wordlist', help='API wordlist')
        tool_group.add_argument('--jsparser-pattern', help='JS parsing pattern')
        tool_group.add_argument('--paramspider-level', choices=['0','1','2'], help='Crawl level')
        tool_group.add_argument('--sqlmap-risk', choices=['1','2','3'], help='Risk level')
        tool_group.add_argument('--help-tool', help='Show tool help')

        # General options
        general_group = parser.add_argument_group('General Options')
        general_group.add_argument('-o', '--output', help='Output directory')
        general_group.add_argument('-w', '--wordlist', help='Wordlist path')
        general_group.add_argument('--timeout', type=int, help='Request timeout')
        general_group.add_argument('--threads', type=int, help='Thread count')
        general_group.add_argument('--rate-limit', type=int, help='Rate limit')
        general_group.add_argument('--delay', type=int, help='Request delay (ms)')
        general_group.add_argument('--debug', action='store_true', help='Debug mode')
        general_group.add_argument('--verbose', action='store_true', help='Verbose output')

        # API keys
        api_group = parser.add_argument_group('API Keys')
        api_group.add_argument('--shodan-key', help='Shodan API key')
        api_group.add_argument('--censys-key', help='Censys API key')
        api_group.add_argument('--virustotal-key', help='VirusTotal API key')
        api_group.add_argument('--securitytrails-key', help='SecurityTrails API key')
        api_group.add_argument('--alienvault-key', help='AlienVault API key')
        api_group.add_argument('--help-api', help='Show API help')

        return parser.parse_args()

    def run(self):
        """Main execution method"""
        try:
            self.print_banner()
            args = self.parse_arguments()

            # Update configuration from command line arguments
            if args.output:
                self.output_dir = args.output
            if args.timeout:
                self.timeout = args.timeout
            if args.threads:
                self.threads = args.threads
            if args.rate_limit:
                self.rate_limit = args.rate_limit

            # Configure logging level
            if args.debug:
                self.logger.setLevel(logging.DEBUG)
            elif args.verbose:
                self.logger.setLevel(logging.INFO)
            
            # Update API keys
            if args.shodan_key:
                self.api_keys['shodan'] = args.shodan_key
            if args.censys_key:
                self.api_keys['censys'] = args.censys_key
            if args.virustotal_key:
                self.api_keys['virustotal'] = args.virustotal_key
            if args.securitytrails_key:
                self.api_keys['securitytrails'] = args.securitytrails_key
            if args.alienvault_key:
                self.api_keys['alienvault'] = args.alienvault_key
                
            # Configure tool options
            self.tool_options.update({
                'httpx': {'extra_options': args.httpx_options} if args.httpx_options else {},
                'katana': {'depth': args.katana_depth},
                'kiterunner': {'wordlist': args.kiterunner_wordlist} if args.kiterunner_wordlist else {},
                'jsparser': {'pattern': args.jsparser_pattern} if args.jsparser_pattern else {},
                'paramspider': {'level': args.paramspider_level},
                'sqlmap': {'risk': args.sqlmap_risk}
            })
            
            # Create session directory
            self.session_dir = self.create_output_dir()
            self.logger.info(f"Results will be saved in: {self.session_dir}")

            # Log API key status
            self.logger.info("Loaded API keys:")
            for api, key in self.api_keys.items():
                self.logger.info(f"    {api.title()}: {'Set' if key else 'Not Set'}")

            try:
                # Execute scans based on arguments
                if args.full or (not args.passive and not args.active and not args.vuln):
                    self.logger.info("Starting complete assessment...")
                    all_subs = self.scanner.passive_recon(args.domain, self.session_dir)
                    alive_hosts = self.scanner.active_scan(args.domain, all_subs, self.session_dir)
                    report_file = self.scanner.vuln_scan(args.domain, alive_hosts, self.session_dir)
                    
                    # Generate HTML report
                    html_report = os.path.join(self.session_dir, "report.html")
                    self.scanner.generate_report(report_file, html_report, self.session_dir)
                    self.logger.info(f"Complete assessment finished! Report: {html_report}")
                
                elif args.passive:
                    self.logger.info("Running passive reconnaissance only...")
                    all_subs = self.scanner.passive_recon(args.domain, self.session_dir)
                    self.logger.info(f"Passive reconnaissance completed. Results in: {all_subs}")
                
                elif args.active:
                    self.logger.info("Running active scanning only...")
                    input_file = args.wordlist or input("[?] Enter path to subdomains file: ")
                    if os.path.exists(input_file):
                        self.scanner.active_scan(args.domain, input_file, self.session_dir)
                    else:
                        self.logger.error(f"Input file not found: {input_file}")
                        sys.exit(1)
                
                elif args.vuln:
                    self.logger.info("Running vulnerability scanning only...")
                    input_file = args.wordlist or input("[?] Enter path to alive hosts file: ")
                    if os.path.exists(input_file):
                        self.scanner.vuln_scan(args.domain, input_file, self.session_dir)
                    else:
                        self.logger.error(f"Input file not found: {input_file}")
                        sys.exit(1)

            except KeyboardInterrupt:
                self.logger.warning("\nScan interrupted by user")
                sys.exit(0)
            except Exception as e:
                self.logger.error(f"An error occurred during scanning: {str(e)}")
                if hasattr(self, 'debug') and self.debug:
                    import traceback
                    self.logger.debug(traceback.format_exc())
                sys.exit(1)

        except Exception as e:
            self.logger.error(f"Critical error: {str(e)}")
            if hasattr(self, 'debug') and self.debug:
                import traceback
                self.logger.debug(traceback.format_exc())
            sys.exit(1)

def main():
    """Main entry point for CodesHacks tool."""
    print("Starting CodesHacks...")
    try:
        tool = CodesHacks()
        tool.run()
        return 0
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        return 130  # Standard Unix practice for Ctrl+C
    except CodesHacksError as e:
        print(f"\n[!] {e.__class__.__name__}: {str(e)}")
        if "--debug" in sys.argv:
            traceback.print_exc()
        return 1
    except Exception as e:
        print(f"\n[!] Unexpected error: {str(e)}")
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())

