#!/usr/bin/env python3
"""
Tools module containing all external tool integrations for CodesHacks
"""

import os
import sys
import subprocess
import json
import logging
from typing import Dict, List, Optional, Union

class ExternalTools:
    def __init__(self, logger: logging.Logger, output_dir: str, options: Dict = None):
        self.logger = logger
        self.output_dir = output_dir
        self.options = options or {}

    def _run_command(self, command: List[str], timeout: int = None, background: bool = False) -> Optional[str]:
        """Run a command and return its output"""
        try:
            if background:
                subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                return None
            
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                text=True,
                check=True
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Command failed: {' '.join(command)}")
            self.logger.error(f"Error: {e.stderr}")
            return None
        except subprocess.TimeoutExpired:
            self.logger.error(f"Command timed out: {' '.join(command)}")
            return None
        except Exception as e:
            self.logger.error(f"Error running command: {e}")
            return None

    def check_tool(self, tool_name: str) -> bool:
        """Check if a tool is installed"""
        try:
            subprocess.run([tool_name, '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return True
        except:
            self.logger.warning(f"{tool_name} not found. Please install it first.")
            return False

    # Web Reconnaissance Tools
    def run_httpx(self, targets: Union[str, List[str]], output_file: str) -> Optional[str]:
        """Run httpx-toolkit on target(s)"""
        if not self.check_tool('httpx'):
            return None

        if isinstance(targets, str):
            targets = [targets]

        command = ['httpx']
        if extra_opts := self.options.get('httpx', {}).get('extra_options'):
            command.extend(extra_opts.split())
        
        command.extend(['-json', '-o', output_file])
        command.extend(targets)

        return self._run_command(command)

    def run_katana(self, target: str, output_file: str) -> Optional[str]:
        """Run katana crawler on target"""
        if not self.check_tool('katana'):
            return None

        depth = self.options.get('katana', {}).get('depth', 10)
        command = [
            'katana',
            '-u', target,
            '-d', str(depth),
            '-jc',  # JSON output
            '-o', output_file
        ]
        return self._run_command(command)

    def run_kiterunner(self, target: str, output_file: str) -> Optional[str]:
        """Run kiterunner for API discovery"""
        if not self.check_tool('kr'):
            return None

        wordlist = self.options.get('kiterunner', {}).get('wordlist', 'routes-large.kite')
        command = [
            'kr',
            'scan',
            target,
            '-w', wordlist,
            '-o', 'json',
            '-j', output_file
        ]
        return self._run_command(command)

    # Intelligence Tools
    def run_assetfinder(self, domain: str, output_file: str) -> Optional[str]:
        """Run assetfinder for subdomain discovery"""
        if not self.check_tool('assetfinder'):
            return None

        command = ['assetfinder', '--subs-only', domain]
        result = self._run_command(command)
        if result:
            with open(output_file, 'w') as f:
                f.write(result)
        return result

    def run_alienvault(self, domain: str, output_file: str) -> Optional[str]:
        """Query AlienVault OTX for domain intelligence"""
        api_key = self.options.get('api_keys', {}).get('alienvault')
        if not api_key:
            self.logger.warning("AlienVault API key not configured")
            return None

        # Implementation using OTX DirectConnect API
        try:
            from OTXv2 import OTXv2
            otx = OTXv2(api_key)
            results = otx.get_passive_dns(domain)
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            return json.dumps(results)
        except ImportError:
            self.logger.error("OTXv2 library not installed. Run: pip install OTXv2")
            return None
        except Exception as e:
            self.logger.error(f"Error querying AlienVault: {e}")
            return None

    # Web Security Tools
    def run_jsparser(self, file_or_url: str, output_file: str) -> Optional[str]:
        """Parse JavaScript files for endpoints and secrets"""
        pattern = self.options.get('jsparser', {}).get('pattern')
        if pattern:
            command = ['jsparser', '-p', pattern]
        else:
            command = ['jsparser']
        
        command.extend(['-f', file_or_url, '-o', output_file])
        return self._run_command(command)

    def run_linkfinder(self, file_or_url: str, output_file: str) -> Optional[str]:
        """Extract endpoints from JavaScript files"""
        if not self.check_tool('linkfinder'):
            return None

        command = [
            'linkfinder',
            '-i', file_or_url,
            '-o', output_file,
            '-d'  # Return only data
        ]
        return self._run_command(command)

    def run_paramspider(self, domain: str, output_file: str) -> Optional[str]:
        """Discover parameters in web applications"""
        if not self.check_tool('paramspider'):
            return None

        level = self.options.get('paramspider', {}).get('level', '1')
        command = [
            'paramspider',
            '-d', domain,
            '-l', level,
            '--output', output_file
        ]
        return self._run_command(command)

    def run_joomscan(self, target: str, output_file: str) -> Optional[str]:
        """Scan Joomla installations"""
        if not self.check_tool('joomscan'):
            return None

        command = [
            'joomscan',
            '--url', target,
            '--report', output_file
        ]
        return self._run_command(command)

    def run_sqlmap(self, target: str, output_dir: str) -> Optional[str]:
        """Run SQL injection tests"""
        if not self.check_tool('sqlmap'):
            return None

        risk = self.options.get('sqlmap', {}).get('risk', '1')
        command = [
            'sqlmap',
            '-u', target,
            '--batch',  # Non-interactive mode
            '--random-agent',  # Random User-Agent
            '--risk', risk,
            '--output-dir', output_dir
        ]
        return self._run_command(command)

    # Utility methods
    def get_version(self, tool: str) -> Optional[str]:
        """Get the version of an installed tool"""
        try:
            result = subprocess.run(
                [tool, '--version'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            return result.stdout.strip() or result.stderr.strip()
        except:
            return None

    def verify_tools(self) -> Dict[str, bool]:
        """Verify all required tools are installed"""
        tools = [
            'httpx',
            'katana',
            'kr',
            'assetfinder',
            'jsparser',
            'linkfinder',
            'paramspider',
            'joomscan',
            'sqlmap'
        ]
        return {tool: self.check_tool(tool) for tool in tools}
