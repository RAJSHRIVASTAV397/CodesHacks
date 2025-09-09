import requests
import logging
import time
from bs4 import BeautifulSoup
import urllib3
import re

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class WebScanner:
    def __init__(self, logger=None):
        self.logger = logger or logging.getLogger(__name__)
        self.paths = ['/', '/robots.txt', '/sitemap.xml']
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate'
        }
    
    def scan(self, domain, output_file):
        """Perform comprehensive web server analysis"""
        self.logger.info(f"Starting web analysis for {domain}")
        
        with open(output_file, 'w') as f:
            f.write(f"Web Server Analysis for {domain}\n")
            f.write("=" * 50 + "\n\n")
            
            for protocol in ['https', 'http']:
                f.write(f"\n{protocol.upper()} Analysis:\n")
                f.write("-" * 20 + "\n")
                
                for path in self.paths:
                    url = f"{protocol}://{domain}{path}"
                    try:
                        session = requests.Session()
                        response = session.get(
                            url,
                            timeout=10,
                            verify=False,
                            headers=self.headers,
                            allow_redirects=True
                        )
                        f.write(f"\nPath: {path}\n")
                        f.write(f"Status: {response.status_code}\n")
                        
                        if response.history:
                            f.write("Redirects:\n")
                            for r in response.history:
                                f.write(f"  {r.status_code} -> {r.url}\n")
                            f.write(f"Final URL: {response.url}\n")
                        
                        f.write("\nHeaders:\n")
                        for header, value in response.headers.items():
                            f.write(f"  {header}: {value}\n")
                        
                        # Analyze homepage content
                        if path == '/' and response.status_code == 200:
                            content_type = response.headers.get('content-type', '').lower()
                            if 'text/html' in content_type:
                                f.write("\nPage Analysis:\n")
                                soup = BeautifulSoup(response.text, 'html.parser')
                                
                                if soup.title:
                                    f.write(f"Title: {soup.title.string.strip()}\n")
                                
                                meta_tags = []
                                for meta in soup.find_all('meta'):
                                    if meta.get('name') and meta.get('content'):
                                        meta_tags.append(f"{meta['name']}: {meta['content']}")
                                
                                if meta_tags:
                                    f.write("\nMeta Tags:\n")
                                    for tag in meta_tags:
                                        f.write(f"  {tag}\n")
                                        
                                # Check for potential vulnerabilities
                                self.check_security_headers(response, f)
                                self.analyze_forms(soup, f)
                        
                    except requests.exceptions.SSLError:
                        f.write(f"\nSSL Error for {url}\n")
                    except requests.exceptions.Timeout:
                        f.write(f"\nTimeout accessing {url}\n")
                    except requests.exceptions.ConnectionError:
                        f.write(f"\nConnection error for {url}\n")
                    except Exception as e:
                        f.write(f"\nError accessing {url}: {str(e)}\n")
                    
                    # Add delay between requests
                    time.sleep(1)
        
        self.logger.info(f"Web analysis completed. Results saved to {output_file}")
        return output_file
    
    def check_security_headers(self, response, f):
        """Check for important security headers"""
        f.write("\nSecurity Headers Analysis:\n")
        security_headers = {
            'X-Frame-Options': 'Missing X-Frame-Options header (clickjacking risk)',
            'X-Content-Type-Options': 'Missing X-Content-Type-Options header (MIME-sniffing risk)',
            'X-XSS-Protection': 'Missing X-XSS-Protection header',
            'Content-Security-Policy': 'Missing Content-Security-Policy header',
            'Strict-Transport-Security': 'Missing HSTS header',
            'Referrer-Policy': 'Missing Referrer-Policy header'
        }
        
        for header, message in security_headers.items():
            if header not in response.headers:
                f.write(f"  WARNING: {message}\n")
            else:
                f.write(f"  {header}: {response.headers[header]}\n")
    
    def analyze_forms(self, soup, f):
        """Analyze HTML forms for potential security issues"""
        forms = soup.find_all('form')
        if forms:
            f.write("\nForm Analysis:\n")
            for form in forms:
                method = form.get('method', 'get').lower()
                action = form.get('action', '')
                f.write(f"  Form found: method={method}, action={action}\n")
                
                if method == 'get':
                    f.write("    WARNING: Form uses GET method\n")
                if not action.startswith('https://'):
                    f.write("    WARNING: Form action does not use HTTPS\n")
                if not form.find('input', {'type': 'hidden', 'name': re.compile(r'csrf|token', re.I)}):
                    f.write("    WARNING: No CSRF token found in form\n")
