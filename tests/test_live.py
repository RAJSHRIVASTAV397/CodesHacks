"""Live testing module for CodesHacks tool."""

import pytest
import os
import sys
import os

# Add parent directory to path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.scanner import Scanner
from codeshacks import CodesHacks
from modules.external_tools import ExternalTools

@pytest.fixture
def external_tools():
    """Fixture for external tools."""
    return ExternalTools()

@pytest.mark.live
def test_dns_enumeration(external_tools):
    """Test DNS enumeration on live target."""
    print("\n=== DNS Enumeration Tests ===")
    
    # Basic DNS enumeration
    scanner = Scanner()
    basic_results = scanner.dns_enum("crypto.com")
    assert basic_results is not None
    print("\nBasic DNS Results:", basic_results)
    
    # DNSRecon
    dnsrecon_file = external_tools.run_dnsrecon("crypto.com")
    if dnsrecon_file:
        print(f"\nDNSRecon results saved to: {dnsrecon_file}")
    
    # Amass
    amass_file = external_tools.run_amass("crypto.com")
    if amass_file:
        print(f"\nAmass results saved to: {amass_file}")

@pytest.mark.live
def test_port_scanning():
    """Test port scanning on live target."""
    print("\n=== Port Scanning Tests ===")
    
    scanner = Scanner()
    results = scanner.port_scan("crypto.com", ports=[80, 443, 53, 8080, 8443])
    assert results is not None
    print("\nPort Scan Results:", results)

@pytest.mark.live
def test_web_analysis(external_tools):
    """Test web server analysis on live target."""
    print("\n=== Web Analysis Tests ===")
    
    # Basic web analysis
    scanner = Scanner()
    basic_results = scanner.web_analyze("crypto.com")
    assert basic_results is not None
    print("\nBasic Web Analysis:", basic_results)
    
    url = "https://crypto.com"
    
    # Directory enumeration tools
    print("\nRunning directory enumeration tools...")
    ferox_file = external_tools.run_feroxbuster(url)
    if ferox_file:
        print(f"Feroxbuster results: {ferox_file}")
        
    ffuf_file = external_tools.run_ffuf(url)
    if ffuf_file:
        print(f"Ffuf results: {ffuf_file}")
        
    gobuster_file = external_tools.run_gobuster(url)
    if gobuster_file:
        print(f"Gobuster results: {gobuster_file}")
    
    # XSS scanning
    print("\nRunning XSS scanner...")
    dalfox_file = external_tools.run_dalfox(url)
    if dalfox_file:
        print(f"Dalfox results: {dalfox_file}")
    
    # Screenshot capture
    print("\nTaking screenshot...")
    screenshot = external_tools.take_screenshot(url)
    if screenshot:
        print(f"Screenshot saved: {screenshot}")
    
    # Wayback Machine
    print("\nChecking Wayback Machine...")
    wayback_file = external_tools.get_wayback_urls("crypto.com")
    if wayback_file:
        print(f"Wayback URLs saved: {wayback_file}")

@pytest.mark.live
def test_full_scan(external_tools):
    """Test full scan functionality with all tools."""
    print("\n=== Full Scan Tests ===")
    
    domain = "crypto.com"
    tool = CodesHacks()
    
    # Create results directory
    results_dir = os.path.join("results", "full_scan")
    os.makedirs(results_dir, exist_ok=True)
    
    try:
        # 1. Basic scan
        basic_results = tool.scan(domain, 
                                ports=[80, 443, 53, 8080, 8443],
                                dns=True,
                                web=True)
        assert basic_results is not None
        print("\nBasic scan completed")
        
        # 2. Advanced DNS enumeration
        print("\nRunning advanced DNS enumeration...")
        external_tools.run_dnsrecon(domain)
        external_tools.run_amass(domain)
        
        # 3. Web scanning
        print("\nRunning web scanning tools...")
        url = f"https://{domain}"
        external_tools.run_feroxbuster(url)
        external_tools.run_ffuf(url)
        external_tools.run_gobuster(url)
        external_tools.run_dalfox(url)
        
        # 4. Historical data
        print("\nGathering historical data...")
        external_tools.get_wayback_urls(domain)
        
        # 5. Visual evidence
        print("\nCapturing visual evidence...")
        external_tools.take_screenshot(url)
        
        print("\nFull scan completed. Check tool_results directory for all findings.")
        
    except Exception as e:
        print(f"Error during full scan: {str(e)}")
        raise
