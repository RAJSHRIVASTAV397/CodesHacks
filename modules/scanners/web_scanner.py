"""Web scanner module for web application analysis."""

from typing import Dict, List, Optional, Any
import aiohttp
import asyncio
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from urllib.parse import urljoin, urlparse

from .base import BaseScanner
from ..core.exceptions import ScanError
from ..core.constants import COMMON_PATHS

class WebScanner(BaseScanner):
    """Scanner for web application analysis."""
    
    def __init__(self, *args, **kwargs):
        """Initialize web scanner."""
        super().__init__(*args, **kwargs)
        self.session = None
        self.driver = None
    
    async def scan(self, target: str, **kwargs: Any) -> Dict[str, Any]:
        """Perform web scan on target.
        
        Args:
            target: Target URL to scan
            **kwargs: Additional scan parameters
                paths: Custom paths to check
                screenshots: Whether to take screenshots
                
        Returns:
            Dict containing findings
            
        Raises:
            ScanError: If scan fails
        """
        self.validate_target(target)
        result = self._create_scan_result()
        
        try:
            # Ensure target has scheme
            if not target.startswith(('http://', 'https://')):
                target = f'http://{target}'
            
            async with aiohttp.ClientSession() as self.session:
                # Basic info gathering
                info = await self._gather_basic_info(target)
                result['findings'].extend(info)
                
                # Directory enumeration
                paths = kwargs.get('paths', COMMON_PATHS)
                dirs = await self._enumerate_directories(target, paths)
                result['findings'].extend(dirs)
                
                # Technology detection
                techs = await self._detect_technologies(target)
                result['findings'].extend(techs)
                
                # Screenshot if requested
                if kwargs.get('screenshots'):
                    screenshots = await self._take_screenshots(target)
                    result['findings'].extend(screenshots)
            
            result['status'] = 'completed'
            return result
            
        except Exception as e:
            error_msg = f"Web scan failed: {str(e)}"
            self.logger.error(error_msg)
            result['status'] = 'error'
            result['errors'].append(error_msg)
            raise ScanError(error_msg)
        finally:
            if self.driver:
                self.driver.quit()
    
    async def _gather_basic_info(self, url: str) -> List[str]:
        """Gather basic information about target.
        
        Args:
            url: Target URL
            
        Returns:
            List of findings
        """
        findings = []
        try:
            async with self.session.get(url, verify_ssl=False) as response:
                findings.append(f"Status: {response.status}")
                
                # Server headers
                for header, value in response.headers.items():
                    findings.append(f"Header - {header}: {value}")
                
                # Parse HTML
                text = await response.text()
                soup = BeautifulSoup(text, 'html.parser')
                
                # Title
                if soup.title:
                    findings.append(f"Title: {soup.title.string.strip()}")
                
                # Meta tags
                for meta in soup.find_all('meta'):
                    if meta.get('name') and meta.get('content'):
                        findings.append(f"Meta - {meta['name']}: {meta['content']}")
        except Exception as e:
            self.logger.error(f"Error gathering basic info: {e}")
        
        return findings
    
    async def _enumerate_directories(self, base_url: str, paths: List[str]) -> List[str]:
        """Check for existence of common directories and files.
        
        Args:
            base_url: Base URL to check
            paths: List of paths to check
            
        Returns:
            List of findings
        """
        findings = []
        
        async def check_path(path: str) -> Optional[str]:
            url = urljoin(base_url, path)
            try:
                async with self.session.get(url, verify_ssl=False) as response:
                    if response.status != 404:
                        return f"Found: {url} ({response.status})"
            except:
                pass
            return None
        
        # Check paths concurrently
        tasks = [check_path(path) for path in paths]
        results = await asyncio.gather(*tasks)
        findings.extend(r for r in results if r)
        
        return findings
    
    async def _detect_technologies(self, url: str) -> List[str]:
        """Detect web technologies in use.
        
        Args:
            url: Target URL
            
        Returns:
            List of detected technologies
        """
        findings = []
        try:
            async with self.session.get(url, verify_ssl=False) as response:
                text = await response.text()
                soup = BeautifulSoup(text, 'html.parser')
                
                # Check headers
                server = response.headers.get('Server')
                if server:
                    findings.append(f"Server: {server}")
                
                powered_by = response.headers.get('X-Powered-By')
                if powered_by:
                    findings.append(f"Powered By: {powered_by}")
                
                # Check for common frameworks
                frameworks = {
                    'WordPress': ['wp-content', 'wp-includes'],
                    'Drupal': ['drupal.js', 'drupal.min.js'],
                    'Joomla': ['joomla.js', 'media/jui'],
                    'Django': ['csrftoken', '__admin'],
                    'Laravel': ['laravel', 'csrf-token'],
                    'React': ['react.js', 'react.min.js'],
                    'Angular': ['ng-', 'angular.js'],
                    'Vue.js': ['vue.js', 'vue.min.js']
                }
                
                for framework, indicators in frameworks.items():
                    if any(i in text for i in indicators):
                        findings.append(f"Framework: {framework}")
                
                # JavaScript libraries
                for script in soup.find_all('script', src=True):
                    src = script['src']
                    findings.append(f"Script: {src}")
                
        except Exception as e:
            self.logger.error(f"Error detecting technologies: {e}")
        
        return findings
    
    async def _take_screenshots(self, url: str) -> List[str]:
        """Take screenshots of target pages.
        
        Args:
            url: Target URL
            
        Returns:
            List of screenshot paths
        """
        findings = []
        try:
            if not self.driver:
                # Setup Chrome
                chrome_options = Options()
                chrome_options.add_argument("--headless")
                chrome_options.add_argument("--no-sandbox")
                chrome_options.add_argument("--disable-dev-shm-usage")
                chrome_options.add_argument("--window-size=1920,1080")
                
                service = Service(ChromeDriverManager().install())
                self.driver = webdriver.Chrome(
                    service=service,
                    options=chrome_options
                )
            
            # Take main page screenshot
            self.driver.get(url)
            screenshot_path = f"screenshots/{urlparse(url).netloc}.png"
            self.driver.save_screenshot(screenshot_path)
            findings.append(f"Screenshot saved: {screenshot_path}")
            
        except Exception as e:
            self.logger.error(f"Error taking screenshots: {e}")
        
        return findings
