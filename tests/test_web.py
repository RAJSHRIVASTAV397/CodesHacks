#!/usr/bin/env python3

import os
import sys
import requests
from datetime import datetime
from bs4 import BeautifulSoup
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def test_web_analysis(domain):
    """Test web server analysis on a domain"""
    print(f"\nTesting web server analysis for {domain}")
    
    # Create output directory
    output_dir = "web_test_results"
    os.makedirs(output_dir, exist_ok=True)
    
    results = []
    
    # Test both HTTP and HTTPS
    for protocol in ['https', 'http']:
        url = f"{protocol}://{domain}"
        print(f"\nTesting {url}")
        results.append(f"\n{protocol.upper()} Analysis:")
        results.append("-" * 20)
        
        try:
            response = requests.get(
                url,
                timeout=10,
                verify=False,
                headers={
                    'User-Agent': 'Mozilla/5.0',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
                },
                allow_redirects=True
            )
            
            # Check redirects
            if response.history:
                results.append("\nRedirect chain:")
                for r in response.history:
                    results.append(f"  {r.url} ({r.status_code})")
                results.append(f"  Final: {response.url}")
            
            results.append(f"\nStatus: {response.status_code}")
            
            # Server headers
            results.append("\nServer Headers:")
            for header, value in response.headers.items():
                results.append(f"  {header}: {value}")
            
            # Content analysis
            content_type = response.headers.get('content-type', '').lower()
            if 'text/html' in content_type:
                results.append("\nAnalyzing HTML content:")
                try:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Title
                    if soup.title:
                        results.append(f"Title: {soup.title.string.strip()}")
                    
                    # Meta tags
                    meta_tags = []
                    for meta in soup.find_all('meta'):
                        if meta.get('name') and meta.get('content'):
                            meta_tags.append(f"{meta['name']}: {meta['content']}")
                    
                    if meta_tags:
                        results.append("\nMeta Tags:")
                        for tag in meta_tags:
                            results.append(f"  {tag}")
                    
                except Exception as e:
                    results.append(f"\nError parsing HTML: {str(e)}")
            else:
                results.append(f"\nNon-HTML response (Content-Type: {content_type})")
            
        except requests.exceptions.SSLError as e:
            results.append(f"SSL Error: {str(e)}")
        except requests.exceptions.Timeout:
            results.append("Error: Connection timed out")
        except requests.exceptions.ConnectionError:
            results.append("Error: Could not connect to server")
        except Exception as e:
            results.append(f"Error: {str(e)}")
        
        results.append("\n" + "-" * 50)
    
    # Check robots.txt and sitemap.xml
    for protocol in ['https', 'http']:
        for path in ['robots.txt', 'sitemap.xml']:
            url = f"{protocol}://{domain}/{path}"
            print(f"\nChecking {url}")
            results.append(f"\nChecking {url}:")
            try:
                response = requests.get(url, timeout=5, verify=False)
                if response.status_code == 200:
                    results.append(response.text[:500] + "..." if len(response.text) > 500 else response.text)
                else:
                    results.append(f"Status: {response.status_code}")
            except Exception as e:
                results.append(f"Error: {str(e)}")
    
    # Save results
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(output_dir, f"web_results_{timestamp}.txt")
    
    with open(output_file, 'w') as f:
        f.write(f"Web Server Analysis Results for {domain}\n")
        f.write("=" * 50 + "\n")
        f.write("\n".join(results))
    
    print(f"\nResults saved to: {output_file}")
    return output_file

if __name__ == "__main__":
    domain = "crypto.com"
    try:
        test_web_analysis(domain)
    except KeyboardInterrupt:
        print("\nTest interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)
