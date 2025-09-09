"""External tools integration module for CodesHacks."""

import os
import subprocess
import shutil
import logging
from datetime import datetime
import sys
from typing import Optional, Dict, List
from pathlib import Path

class ExternalToolError(Exception):
    """Base exception for external tool errors."""
    pass

class ExternalTools:
    """Manages external security tools integration."""
    
    def __init__(self, logger: Optional[logging.Logger] = None, 
                output_dir: str = "results",
                options: Optional[Dict] = None):
        """Initialize external tools manager.
        
        Args:
            logger: Optional logger instance
            output_dir: Directory for tool outputs
            options: Tool-specific options
        """
        self.logger = logger or logging.getLogger(__name__)
        self.output_dir = output_dir
        self.options = options or {}
        
        # Tool paths
        self.tools = {
            'nmap': 'nmap',
            'dnsrecon': 'dnsrecon',
            'amass': 'amass',
            'feroxbuster': 'feroxbuster',
            'ffuf': 'ffuf',
            'gobuster': 'gobuster',
            'dalfox': 'dalfox',
            'nuclei': 'nuclei',
            'sqlmap': 'sqlmap',
            'nikto': 'nikto',
            'wpscan': 'wpscan',
            'subfinder': 'subfinder',
            'httpx': 'httpx',
            'waybackurls': 'waybackurls',
            'gau': 'gau',
            'katana': 'katana',
            'kiterunner': 'kr'
        }
        
        # Initialize tools
        self._check_tools()
        self._init_nuclei()

    def _check_tools(self) -> None:
        """Verify external tools are installed and accessible."""
        missing_tools = []
        
        for tool, command in self.tools.items():
            if not shutil.which(command):
                missing_tools.append(tool)
                
        if missing_tools:
            self.logger.warning("Missing tools: %s", ', '.join(missing_tools))
            self._install_missing_tools(missing_tools)

    def _install_missing_tools(self, tools: List[str]) -> None:
        """Install missing tools.
        
        Args:
            tools: List of tool names to install
        """
        self.logger.info("Installing missing tools...")
        
        for tool in tools:
            try:
                if tool == 'nmap':
                    self._install_package('nmap')
                elif tool == 'dnsrecon':
                    self._run_pip('dnsrecon')
                elif tool == 'amass':
                    self._install_go_tool('github.com/OWASP/Amass/v3/...', 'amass')
                elif tool == 'feroxbuster':
                    self._install_rust_tool('feroxbuster')
                elif tool == 'ffuf':
                    self._install_go_tool('github.com/ffuf/ffuf', 'ffuf')
                elif tool == 'gobuster':
                    self._install_go_tool('github.com/OJ/gobuster/v3', 'gobuster')
                elif tool == 'dalfox':
                    self._install_go_tool('github.com/hahwul/dalfox/v2', 'dalfox')
                elif tool == 'nuclei':
                    self._install_go_tool('github.com/projectdiscovery/nuclei/v2/cmd/nuclei', 'nuclei')
                elif tool == 'sqlmap':
                    self._run_pip('sqlmap')
                elif tool == 'nikto':
                    self._install_package('nikto')
                elif tool == 'wpscan':
                    self._install_gem('wpscan')
                elif tool == 'subfinder':
                    self._install_go_tool('github.com/projectdiscovery/subfinder/v2/cmd/subfinder', 'subfinder')
                elif tool == 'httpx':
                    self._install_go_tool('github.com/projectdiscovery/httpx/cmd/httpx', 'httpx')
                elif tool == 'waybackurls':
                    self._install_go_tool('github.com/tomnomnom/waybackurls', 'waybackurls')
                elif tool == 'gau':
                    self._install_go_tool('github.com/lc/gau/v2/cmd/gau', 'gau')
                elif tool == 'katana':
                    self._install_go_tool('github.com/projectdiscovery/katana/cmd/katana', 'katana')
                elif tool == 'kiterunner':
                    self._install_go_tool('github.com/assetnote/kiterunner/cmd/kr', 'kr')
                
                self.logger.info(f"Successfully installed {tool}")
                
            except Exception as e:
                self.logger.error(f"Failed to install {tool}: {str(e)}")

    def _install_package(self, package: str) -> None:
        """Install system package using package manager."""
        if os.name == 'nt':  # Windows
            subprocess.run(['choco', 'install', '-y', package], check=True)
        else:  # Linux/Unix
            if shutil.which('apt'):
                subprocess.run(['sudo', 'apt', 'install', '-y', package], check=True)
            elif shutil.which('yum'):
                subprocess.run(['sudo', 'yum', 'install', '-y', package], check=True)
            elif shutil.which('pacman'):
                subprocess.run(['sudo', 'pacman', '-S', '--noconfirm', package], check=True)

    def _run_pip(self, package: str) -> None:
        """Install Python package using pip."""
        subprocess.run([sys.executable, '-m', 'pip', 'install', package], check=True)

    def _install_go_tool(self, repo: str, binary: str) -> None:
        """Install Go tool using go install."""
        subprocess.run(['go', 'install', f"{repo}@latest"], check=True)

    def _install_rust_tool(self, tool: str) -> None:
        """Install Rust tool using cargo."""
        subprocess.run(['cargo', 'install', tool], check=True)

    def _install_gem(self, gem: str) -> None:
        """Install Ruby gem."""
        subprocess.run(['gem', 'install', gem], check=True)

    def _init_nuclei(self) -> None:
        """Initialize Nuclei templates."""
        try:
            subprocess.run(['nuclei', '-update-templates'], check=True)
            self.logger.info("Nuclei templates updated successfully")
        except subprocess.CalledProcessError as e:
            self.logger.warning("Failed to update Nuclei templates: %s", str(e))

    def run_dnsrecon(self, domain: str) -> Optional[str]:
        """Run DNSRecon for DNS enumeration.
        
        Args:
            domain: Target domain
            
        Returns:
            Path to output file if successful
        """
        output_file = os.path.join(self.output_dir, f"dnsrecon_{domain}_{self._timestamp()}.xml")
        try:
            subprocess.run([
                'dnsrecon',
                '-d', domain,
                '-t', 'std,bing,crt',
                '-x', output_file,
                '--threads', '10'
            ], check=True)
            return output_file
        except subprocess.CalledProcessError as e:
            self.logger.error("DNSRecon failed: %s", str(e))
            return None

    def run_amass(self, domain: str) -> Optional[str]:
        """Run Amass for subdomain enumeration.
        
        Args:
            domain: Target domain
            
        Returns:
            Path to output file if successful
        """
        output_file = os.path.join(self.output_dir, f"amass_{domain}_{self._timestamp()}.txt")
        try:
            subprocess.run([
                'amass', 'enum',
                '-d', domain,
                '-o', output_file,
                '-timeout', '30'
            ], check=True)
            return output_file
        except subprocess.CalledProcessError as e:
            self.logger.error("Amass failed: %s", str(e))
            return None

    def run_feroxbuster(self, url: str) -> Optional[str]:
        """Run Feroxbuster for directory enumeration.
        
        Args:
            url: Target URL
            
        Returns:
            Path to output file if successful
        """
        output_file = os.path.join(self.output_dir, f"ferox_{self._domain_from_url(url)}_{self._timestamp()}.txt")
        try:
            subprocess.run([
                'feroxbuster',
                '--url', url,
                '--output', output_file,
                '--threads', '50',
                '--depth', '2',
                '--quiet'
            ], check=True)
            return output_file
        except subprocess.CalledProcessError as e:
            self.logger.error("Feroxbuster failed: %s", str(e))
            return None

    def run_ffuf(self, url: str) -> Optional[str]:
        """Run ffuf for web fuzzing.
        
        Args:
            url: Target URL
            
        Returns:
            Path to output file if successful
        """
        output_file = os.path.join(self.output_dir, f"ffuf_{self._domain_from_url(url)}_{self._timestamp()}.json")
        wordlist = "/usr/share/wordlists/dirb/common.txt"  # Default wordlist
        
        try:
            subprocess.run([
                'ffuf',
                '-u', f"{url}/FUZZ",
                '-w', wordlist,
                '-o', output_file,
                '-of', 'json'
            ], check=True)
            return output_file
        except subprocess.CalledProcessError as e:
            self.logger.error("ffuf failed: %s", str(e))
            return None

    def run_gobuster(self, url: str) -> Optional[str]:
        """Run Gobuster for directory enumeration.
        
        Args:
            url: Target URL
            
        Returns:
            Path to output file if successful
        """
        output_file = os.path.join(self.output_dir, f"gobuster_{self._domain_from_url(url)}_{self._timestamp()}.txt")
        wordlist = "/usr/share/wordlists/dirb/common.txt"  # Default wordlist
        
        try:
            subprocess.run([
                'gobuster', 'dir',
                '-u', url,
                '-w', wordlist,
                '-o', output_file,
                '-t', '50'
            ], check=True)
            return output_file
        except subprocess.CalledProcessError as e:
            self.logger.error("Gobuster failed: %s", str(e))
            return None

    def run_dalfox(self, url: str) -> Optional[str]:
        """Run Dalfox for XSS scanning.
        
        Args:
            url: Target URL
            
        Returns:
            Path to output file if successful
        """
        output_file = os.path.join(self.output_dir, f"dalfox_{self._domain_from_url(url)}_{self._timestamp()}.txt")
        try:
            subprocess.run([
                'dalfox', 'url',
                url,
                '--output', output_file,
                '--format', 'text'
            ], check=True)
            return output_file
        except subprocess.CalledProcessError as e:
            self.logger.error("Dalfox failed: %s", str(e))
            return None

    def run_nuclei(self, target: str) -> Optional[str]:
        """Run Nuclei for vulnerability scanning.
        
        Args:
            target: Target URL or domain
            
        Returns:
            Path to output file if successful
        """
        output_file = os.path.join(self.output_dir, f"nuclei_{self._domain_from_url(target)}_{self._timestamp()}.txt")
        try:
            subprocess.run([
                'nuclei',
                '-target', target,
                '-o', output_file,
                '-severity', 'medium,high,critical'
            ], check=True)
            return output_file
        except subprocess.CalledProcessError as e:
            self.logger.error("Nuclei failed: %s", str(e))
            return None

    def run_sqlmap(self, url: str, data: Optional[str] = None) -> Optional[str]:
        """Run SQLMap for SQL injection testing.
        
        Args:
            url: Target URL
            data: Optional POST data
            
        Returns:
            Path to output file if successful
        """
        output_dir = os.path.join(self.output_dir, f"sqlmap_{self._domain_from_url(url)}_{self._timestamp()}")
        try:
            cmd = [
                'sqlmap',
                '-u', url,
                '--batch',
                '--random-agent',
                '--output-dir', output_dir
            ]
            if data:
                cmd.extend(['--data', data])
                
            subprocess.run(cmd, check=True)
            return output_dir
        except subprocess.CalledProcessError as e:
            self.logger.error("SQLMap failed: %s", str(e))
            return None

    def run_nikto(self, url: str) -> Optional[str]:
        """Run Nikto web server scanner.
        
        Args:
            url: Target URL
            
        Returns:
            Path to output file if successful
        """
        output_file = os.path.join(self.output_dir, f"nikto_{self._domain_from_url(url)}_{self._timestamp()}.xml")
        try:
            subprocess.run([
                'nikto',
                '-h', url,
                '-output', output_file,
                '-Format', 'xml'
            ], check=True)
            return output_file
        except subprocess.CalledProcessError as e:
            self.logger.error("Nikto failed: %s", str(e))
            return None

    def run_wpscan(self, url: str, api_token: Optional[str] = None) -> Optional[str]:
        """Run WPScan for WordPress scanning.
        
        Args:
            url: Target WordPress URL
            api_token: Optional WPScan API token
            
        Returns:
            Path to output file if successful
        """
        output_file = os.path.join(self.output_dir, f"wpscan_{self._domain_from_url(url)}_{self._timestamp()}.json")
        try:
            cmd = [
                'wpscan',
                '--url', url,
                '--format', 'json',
                '--output', output_file,
                '--random-user-agent'
            ]
            if api_token:
                cmd.extend(['--api-token', api_token])
                
            subprocess.run(cmd, check=True)
            return output_file
        except subprocess.CalledProcessError as e:
            self.logger.error("WPScan failed: %s", str(e))
            return None

    def run_subfinder(self, domain: str) -> Optional[str]:
        """Run Subfinder for subdomain discovery.
        
        Args:
            domain: Target domain
            
        Returns:
            Path to output file if successful
        """
        output_file = os.path.join(self.output_dir, f"subfinder_{domain}_{self._timestamp()}.txt")
        try:
            subprocess.run([
                'subfinder',
                '-d', domain,
                '-o', output_file,
                '-all'
            ], check=True)
            return output_file
        except subprocess.CalledProcessError as e:
            self.logger.error("Subfinder failed: %s", str(e))
            return None

    def run_httpx(self, input_file: str) -> Optional[str]:
        """Run httpx for HTTP probing.
        
        Args:
            input_file: File containing URLs/domains
            
        Returns:
            Path to output file if successful
        """
        output_file = os.path.join(self.output_dir, f"httpx_{self._timestamp()}.txt")
        try:
            subprocess.run([
                'httpx',
                '-l', input_file,
                '-o', output_file,
                '-title',
                '-status-code',
                '-tech-detect'
            ], check=True)
            return output_file
        except subprocess.CalledProcessError as e:
            self.logger.error("httpx failed: %s", str(e))
            return None

    def take_screenshot(self, url: str) -> Optional[str]:
        """Take screenshot using Chrome headless.
        
        Args:
            url: Target URL
            
        Returns:
            Path to screenshot file if successful
        """
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        
        output_file = os.path.join(self.output_dir, f"screenshot_{self._domain_from_url(url)}_{self._timestamp()}.png")
        
        try:
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--window-size=1920,1080")
            
            driver = webdriver.Chrome(options=chrome_options)
            driver.get(url)
            driver.save_screenshot(output_file)
            driver.quit()
            
            return output_file
            
        except Exception as e:
            self.logger.error("Screenshot failed: %s", str(e))
            return None

    def get_wayback_urls(self, domain: str) -> Optional[str]:
        """Get URLs from Wayback Machine.
        
        Args:
            domain: Target domain
            
        Returns:
            Path to output file if successful
        """
        output_file = os.path.join(self.output_dir, f"wayback_{domain}_{self._timestamp()}.txt")
        try:
            subprocess.run([
                'waybackurls',
                domain,
            ], stdout=open(output_file, 'w'), check=True)
            return output_file
        except subprocess.CalledProcessError as e:
            self.logger.error("waybackurls failed: %s", str(e))
            return None

    def _timestamp(self) -> str:
        """Get current timestamp string."""
        return datetime.now().strftime("%Y%m%d_%H%M%S")

    def _domain_from_url(self, url: str) -> str:
        """Extract domain from URL."""
        from urllib.parse import urlparse
        return urlparse(url).netloc or url
