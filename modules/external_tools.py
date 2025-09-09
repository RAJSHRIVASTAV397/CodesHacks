"""External tools integration module for CodesHacks."""

import os
import subprocess
import json
from datetime import datetime
import logging
import requests
from concurrent.futures import ThreadPoolExecutor

class ExternalTools:
    def __init__(self, logger=None):
        self.logger = logger or logging.getLogger(__name__)
        self.results_dir = "tool_results"
        os.makedirs(self.results_dir, exist_ok=True)

    def check_tool_installed(self, tool_name):
        """Check if a tool is installed and available."""
        try:
            subprocess.run([tool_name, '--version'], 
                         capture_output=True, 
                         check=True)
            return True
        except (subprocess.SubprocessError, FileNotFoundError):
            self.logger.warning(f"{tool_name} not found. Please install it first.")
            return False

    def run_dnsrecon(self, domain):
        """Run dnsrecon for advanced DNS enumeration."""
        if not self.check_tool_installed('dnsrecon'):
            return None

        output_file = os.path.join(self.results_dir, f"dnsrecon_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xml")
        
        try:
            self.logger.info(f"Running dnsrecon against {domain}")
            cmd = [
                'dnsrecon',
                '-d', domain,
                '-t', 'std,rvl,brt,srv,axfr',
                '-x', output_file,
                '--xml', output_file
            ]
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            self.logger.info(f"DNSRecon results saved to {output_file}")
            return output_file
        except subprocess.CalledProcessError as e:
            self.logger.error(f"DNSRecon failed: {str(e)}")
            return None

    def run_feroxbuster(self, url):
        """Run feroxbuster for content discovery."""
        if not self.check_tool_installed('feroxbuster'):
            return None

        output_file = os.path.join(self.results_dir, f"ferox_{url.replace('://', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        
        try:
            self.logger.info(f"Running feroxbuster against {url}")
            cmd = [
                'feroxbuster',
                '--url', url,
                '--silent',
                '--thorough',
                '--auto-bail',
                '--no-recursion',
                '--output', output_file
            ]
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            self.logger.info(f"Feroxbuster results saved to {output_file}")
            return output_file
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Feroxbuster failed: {str(e)}")
            return None

    def run_ffuf(self, url):
        """Run ffuf for content discovery."""
        if not self.check_tool_installed('ffuf'):
            return None

        output_file = os.path.join(self.results_dir, f"ffuf_{url.replace('://', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        
        try:
            self.logger.info(f"Running ffuf against {url}")
            wordlist = "/usr/share/wordlists/dirb/common.txt"  # Default wordlist
            cmd = [
                'ffuf',
                '-u', f"{url}/FUZZ",
                '-w', wordlist,
                '-o', output_file,
                '-of', 'json',
                '-c',
                '-v'
            ]
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            self.logger.info(f"Ffuf results saved to {output_file}")
            return output_file
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Ffuf failed: {str(e)}")
            return None

    def run_gobuster(self, url):
        """Run gobuster for content discovery."""
        if not self.check_tool_installed('gobuster'):
            return None

        output_file = os.path.join(self.results_dir, f"gobuster_{url.replace('://', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        
        try:
            self.logger.info(f"Running gobuster against {url}")
            wordlist = "/usr/share/wordlists/dirb/common.txt"  # Default wordlist
            cmd = [
                'gobuster',
                'dir',
                '-u', url,
                '-w', wordlist,
                '-o', output_file,
                '-q',
                '--no-error'
            ]
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            self.logger.info(f"Gobuster results saved to {output_file}")
            return output_file
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Gobuster failed: {str(e)}")
            return None

    def run_amass(self, domain):
        """Run amass for subdomain enumeration."""
        if not self.check_tool_installed('amass'):
            return None

        output_file = os.path.join(self.results_dir, f"amass_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        
        try:
            self.logger.info(f"Running amass against {domain}")
            cmd = [
                'amass',
                'enum',
                '-d', domain,
                '-o', output_file,
                '-passive'
            ]
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            self.logger.info(f"Amass results saved to {output_file}")
            return output_file
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Amass failed: {str(e)}")
            return None

    def run_dalfox(self, url):
        """Run dalfox for XSS scanning."""
        if not self.check_tool_installed('dalfox'):
            return None

        output_file = os.path.join(self.results_dir, f"dalfox_{url.replace('://', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        
        try:
            self.logger.info(f"Running dalfox against {url}")
            cmd = [
                'dalfox',
                'url', url,
                '--output', output_file,
                '--silence'
            ]
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            self.logger.info(f"Dalfox results saved to {output_file}")
            return output_file
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Dalfox failed: {str(e)}")
            return None

    def get_wayback_urls(self, domain):
        """Get URLs from Wayback Machine with improved error handling."""
        output_file = os.path.join(self.results_dir, f"wayback_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        
        try:
            self.logger.info(f"Fetching Wayback Machine URLs for {domain}")
            
            # Use both CDX API and regular API for better coverage
            cdx_url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
            regular_url = f"http://archive.org/wayback/available?url={domain}"
            
            urls = set()
            
            # Try CDX API first
            try:
                response = requests.get(cdx_url, timeout=30)
                if response.status_code == 200:
                    data = response.json()
                    if data and len(data) > 1:  # First row is header
                        for row in data[1:]:
                            urls.add(row[0])
            except Exception as e:
                self.logger.warning(f"CDX API error: {str(e)}")
            
            # Try regular API
            try:
                response = requests.get(regular_url, timeout=30)
                if response.status_code == 200:
                    data = response.json()
                    snapshots = data.get('archived_snapshots', {})
                    closest = snapshots.get('closest', {})
                    if closest.get('url'):
                        urls.add(closest['url'])
            except Exception as e:
                self.logger.warning(f"Regular API error: {str(e)}")
            
            # Save results
            if urls:
                with open(output_file, 'w') as f:
                    for url in sorted(urls):
                        f.write(f"{url}\n")
                self.logger.info(f"Found {len(urls)} URLs, saved to {output_file}")
                return output_file
            else:
                self.logger.warning("No URLs found in Wayback Machine")
                return None
                
        except Exception as e:
            self.logger.error(f"Wayback Machine error: {str(e)}")
            return None

    def setup_chrome_driver(self):
        """Set up Chrome WebDriver with improved error handling."""
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.service import Service
            from selenium.webdriver.chrome.options import Options
            from webdriver_manager.chrome import ChromeDriverManager
            
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--disable-gpu")
            chrome_options.add_argument("--window-size=1920,1080")
            chrome_options.add_argument("--ignore-certificate-errors")
            
            # Use webdriver_manager to automatically handle ChromeDriver
            service = Service(ChromeDriverManager().install())
            
            driver = webdriver.Chrome(service=service, options=chrome_options)
            driver.set_page_load_timeout(30)
            
            self.logger.info("ChromeDriver setup successful")
            return driver
            
        except Exception as e:
            self.logger.error(f"ChromeDriver setup failed: {str(e)}")
            return None
    
    def take_screenshot(self, url):
        """Take website screenshot with improved error handling."""
        output_file = os.path.join(self.results_dir, f"screenshot_{url.replace('://', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png")
        
        driver = None
        try:
            driver = self.setup_chrome_driver()
            if not driver:
                return None
            
            self.logger.info(f"Taking screenshot of {url}")
            driver.get(url)
            
            # Wait for page to load
            driver.implicitly_wait(10)
            
            # Get page dimensions
            total_width = driver.execute_script("return document.body.offsetWidth")
            total_height = driver.execute_script("return document.body.offsetHeight")
            driver.set_window_size(total_width, total_height)
            
            # Take screenshot
            driver.save_screenshot(output_file)
            self.logger.info(f"Screenshot saved to {output_file}")
            return output_file
            
        except Exception as e:
            self.logger.error(f"Screenshot failed: {str(e)}")
            return None
            
        finally:
            if driver:
                driver.quit()
