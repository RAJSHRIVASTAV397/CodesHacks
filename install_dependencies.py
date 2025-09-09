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
            'requests>=2.33.0',
            'python-nmap>=0.7.2',
            'beautifulsoup4>=4.14.0',
            'configparser>=7.3.0',
            'dnspython>=2.9.0',
            'aiohttp>=3.13.0',
            'selenium>=4.31.0',
            'sslyze>=6.3.0',
            'python-Wappalyzer>=0.4.0',
            'httpx>=0.29.0',
            'urllib3>=2.6.0',
            'shodan>=1.32.0',
            'censys>=2.3.0',
            'vulners>=3.2.0'
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
    
    def upgrade_python_packages(self):
        """Upgrade installed Python packages to latest versions."""
        print("\nUpgrading Python packages...")
        try:
            subprocess.run([sys.executable, '-m', 'pip', 'install', '--upgrade'] + 
                         [req.split('>=')[0] for req in self.get_requirements()],
                         check=True)
            print("Python packages upgraded successfully")
        except subprocess.CalledProcessError as e:
            print(f"Error upgrading Python packages: {e}")
    
    def upgrade_system_packages(self):
        """Upgrade system packages."""
        upgrade_commands = {
            'apt': 'apt update && apt upgrade -y',
            'yum': 'yum update -y',
            'pacman': 'pacman -Syu --noconfirm',
            'brew': 'brew upgrade',
            'choco': 'choco upgrade all -y'
        }
        
        for pm_name, upgrade_cmd in upgrade_commands.items():
            if pm_name in self.package_managers:
                print(f"\nUpgrading packages using {pm_name}...")
                try:
                    if pm_name != 'choco' and self.os_type != 'windows':
                        upgrade_cmd = f"sudo {upgrade_cmd}"
                    subprocess.run(upgrade_cmd.split(), check=True)
                    print(f"Packages upgraded successfully using {pm_name}")
                except subprocess.CalledProcessError as e:
                    print(f"Error upgrading packages with {pm_name}: {e}")
    
    def upgrade_go_tools(self):
        """Upgrade Go-based tools."""
        if not self._cmd_exists('go'):
            print("Go is not installed. Please install Go first.")
            return
            
        print("\nUpgrading Go tools...")
        for tool in [
            'github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest',
            'github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
            'github.com/projectdiscovery/httpx/cmd/httpx@latest',
            'github.com/ffuf/ffuf@latest',
            'github.com/OJ/gobuster/v3@latest'
        ]:
            try:
                subprocess.run(['go', 'install', '-u', tool], check=True)
                print(f"Upgraded {tool.split('/')[-2]}")
            except subprocess.CalledProcessError as e:
                print(f"Error upgrading {tool}: {e}")
    
    def upgrade_rust_tools(self):
        """Upgrade Rust-based tools."""
        if not self._cmd_exists('cargo'):
            print("Rust is not installed. Please install Rust first.")
            return
            
        print("\nUpgrading Rust tools...")
        try:
            subprocess.run(['cargo', 'install-update', '-a'], check=True)
            print("Rust tools upgraded successfully")
        except subprocess.CalledProcessError as e:
            print(f"Error upgrading Rust tools: {e}")
    
    def get_requirements(self) -> List[str]:
        """Get list of required Python packages."""
        return [
            'requests>=2.33.0',
            'python-nmap>=0.7.2',
            'beautifulsoup4>=4.14.0',
            'configparser>=7.3.0',
            'dnspython>=2.9.0',
            'aiohttp>=3.13.0',
            'selenium>=4.31.0',
            'sslyze>=6.3.0',
            'python-Wappalyzer>=0.4.0',
            'httpx>=0.29.0',
            'urllib3>=2.6.0',
            'shodan>=1.32.0',
            'censys>=2.3.0',
            'vulners>=3.2.0'
        ]
    
    def upgrade_all(self):
        """Upgrade all dependencies."""
        print("Starting CodesHacks dependency upgrade...")
        
        # Check if running as root on Unix-like systems
        if self.os_type != 'windows' and os.geteuid() != 0:
            print("Please run this script as root (sudo) for system package upgrades")
            sys.exit(1)
        
        self.upgrade_python_packages()
        self.upgrade_system_packages()
        self.upgrade_go_tools()
        self.upgrade_rust_tools()
        
        print("\nDependency upgrade complete!")
        print("Note: Some tools may require manual upgrade or configuration.")
    
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
    """Main function to handle installation and upgrades."""
    installer = DependencyInstaller()
    
    if len(sys.argv) > 1 and sys.argv[1] == '--upgrade':
        installer.upgrade_all()
    else:
        installer.install_all()

if __name__ == '__main__':
    main()
