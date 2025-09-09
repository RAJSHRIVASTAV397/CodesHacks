#!/usr/bin/env python3

import os
import sys
from datetime import datetime
import test_dns
import test_ports
import test_web

def run_all_tests(domain):
    """Run all tests and combine results"""
    print(f"\nRunning comprehensive test suite for {domain}")
    print("=" * 50)
    
    results = []
    
    # Create main results directory
    output_dir = "comprehensive_test_results"
    os.makedirs(output_dir, exist_ok=True)
    
    try:
        # 1. DNS Enumeration
        print("\n[1/3] Running DNS Enumeration...")
        dns_file = test_dns.test_dns_enum(domain)
        with open(dns_file) as f:
            results.append("\nDNS ENUMERATION RESULTS")
            results.append("=" * 30)
            results.append(f.read())
        
        # 2. Port Scanning
        print("\n[2/3] Running Port Scanning...")
        ports_file = test_ports.test_port_scan(domain)
        with open(ports_file) as f:
            results.append("\nPORT SCANNING RESULTS")
            results.append("=" * 30)
            results.append(f.read())
        
        # 3. Web Analysis
        print("\n[3/3] Running Web Analysis...")
        web_file = test_web.test_web_analysis(domain)
        with open(web_file) as f:
            results.append("\nWEB ANALYSIS RESULTS")
            results.append("=" * 30)
            results.append(f.read())
        
        # Save combined results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(output_dir, f"comprehensive_results_{timestamp}.txt")
        
        with open(output_file, 'w') as f:
            f.write(f"Comprehensive Test Results for {domain}\n")
            f.write("=" * 50 + "\n")
            f.write(f"Test Date: {datetime.now()}\n\n")
            f.write("\n".join(results))
        
        print(f"\nComprehensive results saved to: {output_file}")
        return output_file
        
    except Exception as e:
        print(f"Error during testing: {str(e)}")
        raise

if __name__ == "__main__":
    domain = "crypto.com"
    try:
        run_all_tests(domain)
    except KeyboardInterrupt:
        print("\nTests interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)
