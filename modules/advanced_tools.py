"""Advanced tools integration module for CodesHacks."""

import os
import subprocess
import json
import logging
from datetime import datetime
import requests
import jwt
from urllib.parse import urlparse
import asyncio
import aiohttp

class AdvancedTools:
    def __init__(self, logger=None):
        self.logger = logger or logging.getLogger(__name__)
        self.results_dir = "advanced_results"
        os.makedirs(self.results_dir, exist_ok=True)

    def check_tool_installed(self, tool_name):
        """Check if a tool is installed."""
        try:
            subprocess.run([tool_name, '--version'], 
                         capture_output=True, 
                         check=True)
            return True
        except (subprocess.SubprocessError, FileNotFoundError):
            self.logger.warning(f"{tool_name} not found. Please install it first.")
            return False

    def run_httpx(self, domains_file):
        """Run httpx-toolkit for HTTP probing."""
        if not self.check_tool_installed('httpx'):
            return None

        output_file = os.path.join(self.results_dir, f"httpx_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        
        try:
            self.logger.info("Running httpx...")
            cmd = [
                'httpx',
                '-l', domains_file,
                '-silent',
                '-tech-detect',
                '-title',
                '-web-server',
                '-status-code',
                '-o', output_file
            ]
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            self.logger.info(f"Httpx results saved to {output_file}")
            return output_file
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Httpx failed: {str(e)}")
            return None

    def run_katana(self, url):
        """Run katana crawler."""
        if not self.check_tool_installed('katana'):
            return None

        output_file = os.path.join(self.results_dir, f"katana_{urlparse(url).netloc}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        
        try:
            self.logger.info(f"Running katana on {url}")
            cmd = [
                'katana',
                '-u', url,
                '-jc',  # Enable JavaScript parsing
                '-kf', 'all',  # Enable all field parsing
                '-o', output_file
            ]
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            self.logger.info(f"Katana results saved to {output_file}")
            return output_file
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Katana failed: {str(e)}")
            return None

    async def check_alienvault(self, domain):
        """Query AlienVault OTX for domain information."""
        output_file = os.path.join(self.results_dir, f"alienvault_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        
        try:
            self.logger.info(f"Querying AlienVault OTX for {domain}")
            api_key = os.getenv('ALIENVAULT_API_KEY')
            if not api_key:
                self.logger.error("AlienVault API key not found")
                return None

            headers = {'X-OTX-API-KEY': api_key}
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        with open(output_file, 'w') as f:
                            json.dump(data, f, indent=4)
                        self.logger.info(f"AlienVault results saved to {output_file}")
                        return output_file
                    else:
                        self.logger.error(f"AlienVault API error: {response.status}")
                        return None
        except Exception as e:
            self.logger.error(f"AlienVault query failed: {str(e)}")
            return None

    def analyze_jwt(self, token):
        """Analyze JWT token using jwt.io principles."""
        output_file = os.path.join(self.results_dir, f"jwt_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        
        try:
            self.logger.info("Analyzing JWT token")
            results = []
            
            # Decode token without verification
            decoded = jwt.decode(token, options={"verify_signature": False})
            
            results.append("JWT Token Analysis")
            results.append("=" * 20)
            results.append("\nHeader:")
            results.append(json.dumps(jwt.get_unverified_header(token), indent=4))
            results.append("\nPayload:")
            results.append(json.dumps(decoded, indent=4))
            
            # Basic security checks
            results.append("\nSecurity Analysis:")
            if 'alg' in jwt.get_unverified_header(token):
                alg = jwt.get_unverified_header(token)['alg']
                if alg == 'none':
                    results.append("WARNING: Algorithm 'none' detected - vulnerable to algorithm removal attack")
                elif alg == 'HS256':
                    results.append("INFO: Uses HMAC-SHA256 - ensure strong secret key")
            
            with open(output_file, 'w') as f:
                f.write('\n'.join(results))
            
            self.logger.info(f"JWT analysis saved to {output_file}")
            return output_file
            
        except Exception as e:
            self.logger.error(f"JWT analysis failed: {str(e)}")
            return None

    def run_assetfinder(self, domain):
        """Run assetfinder for asset discovery."""
        if not self.check_tool_installed('assetfinder'):
            return None

        output_file = os.path.join(self.results_dir, f"assetfinder_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        
        try:
            self.logger.info(f"Running assetfinder on {domain}")
            cmd = ['assetfinder', '--subs-only', domain]
            with open(output_file, 'w') as f:
                subprocess.run(cmd, check=True, stdout=f, text=True)
            self.logger.info(f"Assetfinder results saved to {output_file}")
            return output_file
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Assetfinder failed: {str(e)}")
            return None

    def run_linkfinder(self, url):
        """Run LinkFinder to extract endpoints from JavaScript files."""
        if not self.check_tool_installed('linkfinder'):
            return None

        output_file = os.path.join(self.results_dir, f"linkfinder_{urlparse(url).netloc}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
        
        try:
            self.logger.info(f"Running LinkFinder on {url}")
            cmd = [
                'python',
                'LinkFinder/linkfinder.py',
                '-i', url,
                '-o', output_file,
                '-d'
            ]
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            self.logger.info(f"LinkFinder results saved to {output_file}")
            return output_file
        except subprocess.CalledProcessError as e:
            self.logger.error(f"LinkFinder failed: {str(e)}")
            return None

    def run_paramspider(self, domain):
        """Run ParamSpider to find URL parameters."""
        if not self.check_tool_installed('paramspider'):
            return None

        output_file = os.path.join(self.results_dir, f"paramspider_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        
        try:
            self.logger.info(f"Running ParamSpider on {domain}")
            cmd = [
                'python',
                'ParamSpider/paramspider.py',
                '--domain', domain,
                '--output', output_file,
                '--level', 'high'
            ]
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            self.logger.info(f"ParamSpider results saved to {output_file}")
            return output_file
        except subprocess.CalledProcessError as e:
            self.logger.error(f"ParamSpider failed: {str(e)}")
            return None

    def run_spiderfoot(self, domain):
        """Run SpiderFoot for OSINT gathering."""
        if not self.check_tool_installed('spiderfoot'):
            return None

        output_dir = os.path.join(self.results_dir, f"spiderfoot_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        os.makedirs(output_dir, exist_ok=True)
        
        try:
            self.logger.info(f"Running SpiderFoot on {domain}")
            cmd = [
                'spiderfoot',
                '-s', domain,
                '-m', 'ALL',
                '-o', output_dir,
                '-f', 'ALL'
            ]
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            self.logger.info(f"SpiderFoot results saved to {output_dir}")
            return output_dir
        except subprocess.CalledProcessError as e:
            self.logger.error(f"SpiderFoot failed: {str(e)}")
            return None

    def run_joomscan(self, url):
        """Run JoomScan for Joomla vulnerability scanning."""
        if not self.check_tool_installed('joomscan'):
            return None

        output_file = os.path.join(self.results_dir, f"joomscan_{urlparse(url).netloc}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        
        try:
            self.logger.info(f"Running JoomScan on {url}")
            cmd = [
                'perl',
                'joomscan/joomscan.pl',
                '--url', url,
                '--report', output_file
            ]
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            self.logger.info(f"JoomScan results saved to {output_file}")
            return output_file
        except subprocess.CalledProcessError as e:
            self.logger.error(f"JoomScan failed: {str(e)}")
            return None

    def run_sqlmap(self, url, data=None):
        """Run SQLMap for SQL injection testing."""
        if not self.check_tool_installed('sqlmap'):
            return None

        output_dir = os.path.join(self.results_dir, f"sqlmap_{urlparse(url).netloc}_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        
        try:
            self.logger.info(f"Running SQLMap on {url}")
            cmd = [
                'sqlmap',
                '-u', url,
                '--batch',
                '--random-agent',
                '--output-dir', output_dir
            ]
            
            if data:
                cmd.extend(['--data', data])
                
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            self.logger.info(f"SQLMap results saved to {output_dir}")
            return output_dir
        except subprocess.CalledProcessError as e:
            self.logger.error(f"SQLMap failed: {str(e)}")
            return None

    def run_kiterunner(self, target):
        """Run Kiterunner for API endpoint discovery."""
        if not self.check_tool_installed('kr'):
            return None

        output_file = os.path.join(self.results_dir, f"kiterunner_{urlparse(target).netloc}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        
        try:
            self.logger.info(f"Running Kiterunner on {target}")
            cmd = [
                'kr',
                'scan',
                target,
                '-w', 'routes/swagger.json',  # Default API wordlist
                '-o', output_file,
                '--fail-status-codes', '400,401,404,403,501,502,426,411'
            ]
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            self.logger.info(f"Kiterunner results saved to {output_file}")
            return output_file
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Kiterunner failed: {str(e)}")
            return None
