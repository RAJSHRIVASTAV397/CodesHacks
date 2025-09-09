"""Unified security tools integration module for CodesHacks."""

import os
import subprocess
import shutil
import logging
import sys
from datetime import datetime
from typing import Optional, Dict, List, Union, Any
from pathlib import Path
from urllib.parse import urlparse
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from ..config_manager import ConfigManager

class ToolError(Exception):
    """Base exception for tool errors."""
    pass

class UnifiedTools:
    """Unified manager for all security tools."""
    
    def __init__(self, logger: Optional[logging.Logger] = None, 
                output_dir: str = "results",
                options: Optional[Dict] = None):
        """Initialize unified tools manager.
        
        Args:
            logger: Optional logger instance
            output_dir: Directory for tool outputs
            options: Tool-specific options
        """
        self.logger = logger or logging.getLogger(__name__)
        self.output_dir = output_dir
        self.options = options or {}
        
        # Initialize configuration manager
        self.config_manager = ConfigManager(logger=self.logger)
        # Load general settings
        general_config = self.config_manager.config['general']
        self.output_dir = general_config.get('output_dir', output_dir)
        self.max_threads = general_config.get('max_threads', 10)
        self.debug = general_config.get('debug', False)
        self.proxy = general_config.get('proxy', None)
        self.user_agent = general_config.get('user_agent', 'CodesHacks Security Scanner')
        
        # Unified tools registry
        self.tools = {
            # Core Security Tools
            'nmap': 'nmap',
            'dnsrecon': 'dnsrecon',
            'amass': 'amass',
            'nuclei': 'nuclei',
            'sqlmap': 'sqlmap',
            'nikto': 'nikto',
            'wpscan': 'wpscan',
            'subfinder': 'subfinder',
            'httpx': 'httpx',
            'feroxbuster': 'feroxbuster',
            'ffuf': 'ffuf',
            'gobuster': 'gobuster',
            'dalfox': 'dalfox',
            'waybackurls': 'waybackurls',
            'gau': 'gau',
            'katana': 'katana',
            'kiterunner': 'kr',
            
            # Web Application Testing
            'burpsuite': 'burpsuite',
            'zap': 'zap-cli',
            'arachni': 'arachni',
            
            # Network Security
            'metasploit': 'msfconsole',
            'wireshark': 'wireshark-cli',
            'hydra': 'hydra',
            'aircrack-ng': 'aircrack-ng',
            
            # Forensics
            'volatility': 'vol.py',
            'autopsy': 'autopsy',
            'sleuthkit': 'mmls',
            
            # Reverse Engineering
            'ghidra': 'ghidra',
            'radare2': 'r2',
            'ida': 'ida64',
            
            # Cloud Security
            'cloudsploit': 'cloudsploit',
            'prowler': 'prowler',
            'pacu': 'pacu',
            
            # Mobile Security
            'mobsf': 'mobsf',
            'apktool': 'apktool',
            'frida': 'frida',
            
            # IoT Security
            'firmwalker': 'firmwalker',
            'binwalk': 'binwalk',
            
            # Container Security
            'trivy': 'trivy',
            'grype': 'grype',
            'syft': 'syft'
        }
        
        # Initialize
        self._check_tools()
        self._init_nuclei()

    def _check_tools(self) -> None:
        """Verify and install tools."""
        missing_tools = []
        for tool, command in self.tools.items():
            if not self._is_tool_installed(command):
                missing_tools.append(tool)
        
        if missing_tools:
            self.logger.warning(f"Missing tools: {', '.join(missing_tools)}")
            self._install_missing_tools(missing_tools)

    def _is_tool_installed(self, command: str) -> bool:
        """Check if a tool is installed."""
        return shutil.which(command) is not None

    def _install_missing_tools(self, tools: List[str]) -> None:
        """Install missing tools."""
        for tool in tools:
            try:
                self.logger.info(f"Installing {tool}...")
                
                # Core security tools
                if tool in ['nmap', 'nikto', 'hydra']:
                    self._install_package(tool)
                elif tool in ['dnsrecon', 'sqlmap']:
                    self._run_pip(tool)
                elif tool in ['amass', 'subfinder', 'httpx', 'nuclei']:
                    self._install_go_tool(f'github.com/projectdiscovery/{tool}/v2/cmd/{tool}', tool)
                elif tool in ['feroxbuster']:
                    self._install_rust_tool(tool)
                elif tool == 'wpscan':
                    self._install_gem(tool)
                    
                # Advanced security tools
                elif tool in ['burpsuite', 'zap']:
                    self._install_java_tool(tool)
                elif tool in ['volatility', 'autopsy']:
                    self._install_forensics_tool(tool)
                elif tool in ['ghidra', 'radare2']:
                    self._install_reverse_tool(tool)
                elif tool in ['cloudsploit', 'prowler']:
                    self._install_cloud_tool(tool)
                elif tool in ['mobsf', 'apktool']:
                    self._install_mobile_tool(tool)
                elif tool in ['trivy', 'grype', 'syft']:
                    self._install_container_tool(tool)
                
                self.logger.info(f"Successfully installed {tool}")
            except Exception as e:
                self.logger.error(f"Failed to install {tool}: {str(e)}")

    def _init_nuclei(self) -> None:
        """Initialize Nuclei templates."""
        try:
            subprocess.run(['nuclei', '-update-templates'], check=True)
            self.logger.info("Nuclei templates updated successfully")
        except subprocess.CalledProcessError as e:
            self.logger.warning(f"Failed to update Nuclei templates: {str(e)}")

    # Tool Installation Methods
    def _install_package(self, package: str) -> None:
        """Install system package."""
        if os.name == 'nt':  # Windows
            subprocess.run(['choco', 'install', '-y', package], check=True)
        else:  # Linux
            if shutil.which('apt'):
                subprocess.run(['sudo', 'apt', 'install', '-y', package], check=True)
            elif shutil.which('yum'):
                subprocess.run(['sudo', 'yum', 'install', '-y', package], check=True)
            elif shutil.which('pacman'):
                subprocess.run(['sudo', 'pacman', '-S', '--noconfirm', package], check=True)

    def _run_pip(self, package: str) -> None:
        """Install Python package."""
        subprocess.run([sys.executable, '-m', 'pip', 'install', package], check=True)

    def _install_go_tool(self, repo: str, binary: str) -> None:
        """Install Go tool."""
        subprocess.run(['go', 'install', f"{repo}@latest"], check=True)

    def _install_rust_tool(self, tool: str) -> None:
        """Install Rust tool."""
        subprocess.run(['cargo', 'install', tool], check=True)

    def _install_gem(self, gem: str) -> None:
        """Install Ruby gem."""
        subprocess.run(['gem', 'install', gem], check=True)

    def _install_java_tool(self, tool: str) -> None:
        """Install Java-based tools."""
        if tool == 'burpsuite':
            subprocess.run(['curl', '-L', '-o', 'burpsuite_pro.jar',
                          'https://portswigger.net/burp/releases/download'],
                         check=True)
        elif tool == 'zap':
            subprocess.run(['snap', 'install', 'zaproxy', '--classic'], check=True)

    def _install_forensics_tool(self, tool: str) -> None:
        """Install forensics tools."""
        if tool == 'volatility':
            subprocess.run(['pip', 'install', 'volatility3'], check=True)
        elif tool == 'autopsy':
            self._install_package('autopsy')

    def _install_reverse_tool(self, tool: str) -> None:
        """Install reverse engineering tools."""
        if tool == 'ghidra':
            subprocess.run(['wget', 'https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.1.2_build/ghidra_10.1.2_PUBLIC_20220125.zip'], check=True)
        elif tool == 'radare2':
            subprocess.run(['git', 'clone', 'https://github.com/radareorg/radare2'], check=True)
            subprocess.run(['./radare2/sys/install.sh'], check=True)

    def _install_cloud_tool(self, tool: str) -> None:
        """Install cloud security tools."""
        if tool == 'cloudsploit':
            subprocess.run(['npm', 'install', '-g', 'cloudsploit'], check=True)
        elif tool == 'prowler':
            subprocess.run(['pip', 'install', 'prowler'], check=True)

    def _install_mobile_tool(self, tool: str) -> None:
        """Install mobile security tools."""
        if tool == 'mobsf':
            subprocess.run(['docker', 'pull', 'opensecurity/mobile-security-framework-mobsf'], check=True)
        elif tool == 'apktool':
            self._install_package('apktool')

    def _install_container_tool(self, tool: str) -> None:
        """Install container security tools."""
        if tool == 'trivy':
            subprocess.run(['curl', '-sfL', 'https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh', '|', 'sh', '-s', '--', '-b', '/usr/local/bin'], check=True)
        elif tool in ['grype', 'syft']:
            subprocess.run(['curl', '-sSfL', f'https://raw.githubusercontent.com/anchore/{tool}/main/install.sh', '|', 'sh', '-s', '--', '-b', '/usr/local/bin'], check=True)

    # Core Security Tool Methods
    def run_dnsrecon(self, domain: str) -> Optional[str]:
        """Run DNSRecon for DNS enumeration."""
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
            self.logger.error(f"DNSRecon failed: {str(e)}")
            return None

    def run_nuclei(self, target: str) -> Optional[str]:
        """Run Nuclei for vulnerability scanning."""
        output_file = os.path.join(self.output_dir, f"nuclei_{self._domain_from_url(target)}_{self._timestamp()}.txt")
        
        # Get tool-specific configuration
        config = self.config_manager.get_tool_config('nuclei')
        templates = ','.join(config.get('templates', ['cves', 'vulnerabilities', 'misconfiguration']))
        severity = ','.join(config.get('severity', ['critical', 'high', 'medium']))
        rate_limit = config.get('rate_limit', 150)
        timeout = config.get('timeout', 5)
        retries = config.get('retries', 3)
        
        try:
            cmd = [
                'nuclei',
                '-target', target,
                '-o', output_file,
                '-severity', severity,
                '-t', templates,
                '-rl', str(rate_limit),
                '-timeout', str(timeout),
                '-retries', str(retries)
            ]
            
            if self.proxy:
                cmd.extend(['-proxy', self.proxy])
                
            if self.debug:
                cmd.append('-debug')
                
            subprocess.run(cmd, check=True)
            self.logger.info(f"Nuclei scan completed: {output_file}")
            return output_file
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Nuclei failed: {str(e)}")
            return None

    def run_sqlmap(self, url: str, data: Optional[str] = None) -> Optional[str]:
        """Run SQLMap for SQL injection testing."""
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
            self.logger.error(f"SQLMap failed: {str(e)}")
            return None

    def run_subfinder(self, domain: str) -> Optional[str]:
        """Run Subfinder for subdomain discovery."""
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
            self.logger.error(f"Subfinder failed: {str(e)}")
            return None

    # Advanced Security Tool Methods
    def run_burpsuite_scan(self, target: str) -> Optional[str]:
        """Run Burp Suite automated scan."""
        output_file = os.path.join(self.output_dir, f"burp_{self._timestamp()}.html")
        try:
            subprocess.run([
                'java', '-jar', 'burpsuite_pro.jar',
                '--project-file=temp.burp',
                '--unpause-spider-and-scanner',
                f'--target={target}',
                f'--report-file={output_file}'
            ], check=True)
            return output_file
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Burp Suite scan failed: {str(e)}")
            return None

    def run_metasploit_scan(self, target: str, exploit: str) -> Optional[str]:
        """Run Metasploit scan/exploit."""
        output_file = os.path.join(self.output_dir, f"msf_{self._timestamp()}.txt")
        rc_file = self._create_msf_resource_file(target, exploit)
        
        try:
            subprocess.run([
                'msfconsole', '-q',
                '-r', rc_file,
                '-o', output_file
            ], check=True)
            return output_file
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Metasploit scan failed: {str(e)}")
            return None

    def run_mobsf_analysis(self, app_file: str) -> Optional[str]:
        """Run MobSF mobile app analysis."""
        output_file = os.path.join(self.output_dir, f"mobsf_{self._timestamp()}.pdf")
        try:
            subprocess.run([
                'mobsf',
                '--file', app_file,
                '--output', output_file,
                '--format', 'pdf'
            ], check=True)
            return output_file
        except subprocess.CalledProcessError as e:
            self.logger.error(f"MobSF analysis failed: {str(e)}")
            return None

    def run_trivy_scan(self, target: str) -> Optional[str]:
        """Run Trivy container security scan."""
        output_file = os.path.join(self.output_dir, f"trivy_{self._timestamp()}.json")
        try:
            subprocess.run([
                'trivy',
                '--format', 'json',
                '--output', output_file,
                target
            ], check=True)
            return output_file
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Trivy scan failed: {str(e)}")
            return None

    # Utility Methods
    def _create_msf_resource_file(self, target: str, exploit: str) -> str:
        """Create Metasploit resource file."""
        rc_content = f"""
use {exploit}
set RHOSTS {target}
run
exit
"""
        rc_file = os.path.join(self.output_dir, "msf_temp.rc")
        with open(rc_file, 'w') as f:
            f.write(rc_content)
        return rc_file

    def _timestamp(self) -> str:
        """Get current timestamp string."""
        return datetime.now().strftime("%Y%m%d_%H%M%S")

    def _domain_from_url(self, url: str) -> str:
        """Extract domain from URL."""
        return urlparse(url).netloc or url
        
    def configure_tool(self, tool_name: str, config: Dict[str, Any]) -> bool:
        """Update configuration for a specific tool.
        
        Args:
            tool_name: Name of the tool to configure
            config: New configuration dictionary
            
        Returns:
            bool: True if configuration was updated successfully
        """
        if tool_name not in self.tools:
            self.logger.error(f"Unknown tool: {tool_name}")
            return False
            
        return self.config_manager.update_tool_config(tool_name, config)
        
    def set_api_key(self, service: str, key: str) -> bool:
        """Set API key for a service.
        
        Args:
            service: Service name (e.g., 'shodan', 'censys')
            key: API key
            
        Returns:
            bool: True if API key was set successfully
        """
        return self.config_manager.set_api_key(service, key)
        
    def update_general_settings(self, settings: Dict[str, Any]) -> bool:
        """Update general tool settings.
        
        Args:
            settings: Dictionary of settings to update
            
        Returns:
            bool: True if settings were updated successfully
        """
        if self.config_manager.update_general_config(settings):
            # Update local settings
            general_config = self.config_manager.config['general']
            self.output_dir = general_config.get('output_dir', self.output_dir)
            self.max_threads = general_config.get('max_threads', self.max_threads)
            self.debug = general_config.get('debug', self.debug)
            self.proxy = general_config.get('proxy', self.proxy)
            self.user_agent = general_config.get('user_agent', self.user_agent)
            return True
        return False
