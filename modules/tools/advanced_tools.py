"""Advanced security tools integration module for CodesHacks."""

import os
import subprocess
import logging
from datetime import datetime
from typing import Optional, Dict, List
from pathlib import Path

class AdvancedToolError(Exception):
    """Base exception for advanced tool errors."""
    pass

class AdvancedTools:
    """Manages advanced security tools integration."""
    
    def __init__(self, logger: Optional[logging.Logger] = None, 
                output_dir: str = "results",
                options: Optional[Dict] = None):
        """Initialize advanced tools manager.
        
        Args:
            logger: Optional logger instance
            output_dir: Directory for tool outputs
            options: Tool-specific options
        """
        self.logger = logger or logging.getLogger(__name__)
        self.output_dir = output_dir
        self.options = options or {}
        
        # Advanced tools configuration
        self.tools = {
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
        
        # Check and install tools
        self._check_tools()

    def _check_tools(self) -> None:
        """Verify and install advanced tools."""
        missing_tools = []
        for tool, command in self.tools.items():
            if not self._is_tool_installed(command):
                missing_tools.append(tool)
        
        if missing_tools:
            self.logger.warning(f"Missing advanced tools: {', '.join(missing_tools)}")
            self._install_missing_tools(missing_tools)

    def _is_tool_installed(self, command: str) -> bool:
        """Check if a tool is installed."""
        try:
            subprocess.run([command, '--version'], 
                         stdout=subprocess.PIPE, 
                         stderr=subprocess.PIPE)
            return True
        except FileNotFoundError:
            return False

    def _install_missing_tools(self, tools: List[str]) -> None:
        """Install missing advanced tools."""
        for tool in tools:
            try:
                self.logger.info(f"Installing {tool}...")
                if tool in ['burpsuite', 'zap']:
                    self._install_java_tool(tool)
                elif tool in ['metasploit', 'wireshark']:
                    self._install_package(tool)
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

    def run_burpsuite_scan(self, target: str) -> Optional[str]:
        """Run Burp Suite automated scan.
        
        Args:
            target: Target URL
            
        Returns:
            Path to scan report
        """
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

    def run_zap_scan(self, target: str, api_key: str) -> Optional[str]:
        """Run OWASP ZAP scan.
        
        Args:
            target: Target URL
            api_key: ZAP API key
            
        Returns:
            Path to scan report
        """
        output_file = os.path.join(self.output_dir, f"zap_{self._timestamp()}.html")
        try:
            subprocess.run([
                'zap-cli', '--api-key', api_key,
                'quick-scan', '-s', 'all',
                '--spider', target,
                '--report', output_file
            ], check=True)
            return output_file
        except subprocess.CalledProcessError as e:
            self.logger.error(f"ZAP scan failed: {str(e)}")
            return None

    def run_metasploit_scan(self, target: str, exploit: str) -> Optional[str]:
        """Run Metasploit scan/exploit.
        
        Args:
            target: Target host
            exploit: Metasploit exploit path
            
        Returns:
            Path to scan report
        """
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

    def run_volatility_analysis(self, memory_dump: str) -> Optional[str]:
        """Run Volatility memory analysis.
        
        Args:
            memory_dump: Path to memory dump file
            
        Returns:
            Path to analysis report
        """
        output_dir = os.path.join(self.output_dir, f"vol_{self._timestamp()}")
        os.makedirs(output_dir, exist_ok=True)
        
        try:
            for plugin in ['pslist', 'netscan', 'malfind']:
                subprocess.run([
                    'vol.py', '-f', memory_dump,
                    plugin,
                    '--output-file', os.path.join(output_dir, f"{plugin}.txt")
                ], check=True)
            return output_dir
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Volatility analysis failed: {str(e)}")
            return None

    def run_mobsf_analysis(self, app_file: str) -> Optional[str]:
        """Run MobSF mobile app analysis.
        
        Args:
            app_file: Path to APK/IPA file
            
        Returns:
            Path to analysis report
        """
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
        """Run Trivy container security scan.
        
        Args:
            target: Container image or filesystem path
            
        Returns:
            Path to scan report
        """
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

    def run_prowler_scan(self, profile: str) -> Optional[str]:
        """Run Prowler AWS security assessment.
        
        Args:
            profile: AWS profile name
            
        Returns:
            Path to scan report
        """
        output_file = os.path.join(self.output_dir, f"prowler_{self._timestamp()}")
        try:
            subprocess.run([
                'prowler',
                '--profile', profile,
                '--output-file', output_file,
                '--output-format', 'html,json'
            ], check=True)
            return output_file
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Prowler scan failed: {str(e)}")
            return None

    def run_binwalk_analysis(self, firmware: str) -> Optional[str]:
        """Run Binwalk firmware analysis.
        
        Args:
            firmware: Path to firmware file
            
        Returns:
            Path to analysis report
        """
        output_dir = os.path.join(self.output_dir, f"binwalk_{self._timestamp()}")
        try:
            subprocess.run([
                'binwalk',
                '-Me', firmware,
                '--directory', output_dir
            ], check=True)
            return output_dir
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Binwalk analysis failed: {str(e)}")
            return None

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

    def _install_java_tool(self, tool: str) -> None:
        """Install Java-based tools."""
        if tool == 'burpsuite':
            subprocess.run(['curl', '-L', '-o', 'burpsuite_pro.jar',
                          'https://portswigger.net/burp/releases/download'],
                         check=True)
        elif tool == 'zap':
            subprocess.run(['snap', 'install', 'zaproxy', '--classic'], check=True)

    def _install_package(self, package: str) -> None:
        """Install system package."""
        if os.name == 'nt':  # Windows
            subprocess.run(['choco', 'install', '-y', package], check=True)
        else:  # Linux
            subprocess.run(['sudo', 'apt', 'install', '-y', package], check=True)

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
