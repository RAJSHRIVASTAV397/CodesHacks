#!/usr/bin/env python3
"""Tool dependency installer for CodesHacks."""

import os
import sys
import subprocess
import platform
from typing import List, Dict

class DependencyInstaller:
    """Handles installation of tool dependencies."""
    
    def __init__(self):
        self.os_type = platform.system().lower()
        self.package_managers = self._detect_package_managers()
        
    def _detect_package_managers(self) -> Dict[str, str]:
        """Detect available package managers."""
        package_managers = {}
        
        if self.os_type == 'linux':
            # Debian/Ubuntu
            if self._cmd_exists('apt'):
                package_managers['apt'] = 'apt install -y'
            # RHEL/CentOS/Fedora
            elif self._cmd_exists('yum'):
                package_managers['yum'] = 'yum install -y'
            # Arch Linux
            elif self._cmd_exists('pacman'):
                package_managers['pacman'] = 'pacman -S --noconfirm'
                
        elif self.os_type == 'darwin':  # macOS
            if self._cmd_exists('brew'):
                package_managers['brew'] = 'brew install'
                
        elif self.os_type == 'windows':
            if self._cmd_exists('choco'):
                package_managers['choco'] = 'choco install -y'
                
        return package_managers
    
    def _cmd_exists(self, cmd: str) -> bool:
        """Check if a command exists."""
        return subprocess.run(['which', cmd], 
                           stdout=subprocess.PIPE, 
                           stderr=subprocess.PIPE).returncode == 0
    
    def install_python_packages(self):
        """Install required Python packages."""
        requirements = [
            'requests>=2.32.5',
            'python-nmap>=0.7.1',
            'beautifulsoup4>=4.13.5',
            'configparser>=7.2.0',
            'dnspython>=2.8.0',
            'aiohttp>=3.12.15',
            'selenium>=4.30.0',
            'sslyze>=6.2.0',
            'python-Wappalyzer>=0.3.1',
            'httpx>=0.28.1',
            'urllib3>=2.5.0',
            'shodan>=1.31.0',
            'censys>=2.2.18',
            'vulners>=3.1.0'
        ]
        
        print("Installing Python packages...")
        try:
            subprocess.run([sys.executable, '-m', 'pip', 'install'] + requirements,
                         check=True)
            print("Python packages installed successfully")
        except subprocess.CalledProcessError as e:
            print(f"Error installing Python packages: {e}")
            sys.exit(1)
    
    def install_system_packages(self):
        """Install required system packages."""
        packages = {
            'apt': [
                'nmap',
                'nikto',
                'wpscan',
                'hydra',
                'binwalk',
                'wireshark',
                'radare2'
            ],
            'yum': [
                'nmap',
                'nikto',
                'hydra',
                'binwalk',
                'wireshark',
                'radare2'
            ],
            'pacman': [
                'nmap',
                'nikto',
                'hydra',
                'binwalk',
                'wireshark',
                'radare2'
            ],
            'brew': [
                'nmap',
                'nikto',
                'hydra',
                'binwalk',
                'wireshark',
                'radare2'
            ],
            'choco': [
                'nmap',
                'nikto',
                'wireshark'
            ]
        }
        
        for pm_name, pm_cmd in self.package_managers.items():
            if pm_name in packages:
                print(f"\nInstalling packages using {pm_name}...")
                for package in packages[pm_name]:
                    try:
                        cmd = f"sudo {pm_cmd} {package}" if pm_name != 'choco' else f"{pm_cmd} {package}"
                        subprocess.run(cmd.split(), check=True)
                        print(f"Installed {package}")
                    except subprocess.CalledProcessError as e:
                        print(f"Error installing {package}: {e}")
    
    def install_go_tools(self):
        """Install Go-based tools."""
        go_tools = [
            'github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest',
            'github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
            'github.com/projectdiscovery/httpx/cmd/httpx@latest',
            'github.com/ffuf/ffuf@latest',
            'github.com/OJ/gobuster/v3@latest'
        ]
        
        if not self._cmd_exists('go'):
            print("Go is not installed. Please install Go first.")
            return
        
        print("\nInstalling Go tools...")
        for tool in go_tools:
            try:
                subprocess.run(['go', 'install', tool], check=True)
                print(f"Installed {tool.split('/')[-2]}")
            except subprocess.CalledProcessError as e:
                print(f"Error installing {tool}: {e}")
    
    def install_rust_tools(self):
        """Install Rust-based tools."""
        rust_tools = ['feroxbuster']
        
        if not self._cmd_exists('cargo'):
            print("Rust is not installed. Please install Rust first.")
            return
        
        print("\nInstalling Rust tools...")
        for tool in rust_tools:
            try:
                subprocess.run(['cargo', 'install', tool], check=True)
                print(f"Installed {tool}")
            except subprocess.CalledProcessError as e:
                print(f"Error installing {tool}: {e}")
    
    def install_all(self):
        """Install all dependencies."""
        print("Starting CodesHacks dependency installation...")
        
        # Check if running as root on Unix-like systems
        if self.os_type != 'windows' and os.geteuid() != 0:
            print("Please run this script as root (sudo) for system package installation")
            sys.exit(1)
        
        self.install_python_packages()
        self.install_system_packages()
        self.install_go_tools()
        self.install_rust_tools()
        
        print("\nDependency installation complete!")
        print("Note: Some tools may require manual installation or configuration.")

def main():
    installer = DependencyInstaller()
    installer.install_all()

if __name__ == '__main__':
    main()
