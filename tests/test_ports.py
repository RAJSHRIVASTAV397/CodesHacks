#!/usr/bin/env python3

import os
import sys
import socket
from datetime import datetime

def test_port_scan(domain):
    """Test port scanning on a domain"""
    print(f"\nTesting port scanning for {domain}")
    
    # Create output directory
    output_dir = "port_test_results"
    os.makedirs(output_dir, exist_ok=True)
    
    results = []
    
    try:
        # Resolve domain to IP
        print(f"\nResolving {domain}...")
        ip = socket.gethostbyname(domain)
        print(f"Resolved to {ip}")
        results.append(f"Target: {domain} ({ip})")
    except socket.gaierror:
        print(f"Could not resolve {domain}")
        return
    
    # Common ports to check
    common_ports = [
        20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
        3306, 3389, 5432, 8080, 8443
    ]
    
    results.append("\nPort Scan Results:")
    results.append("-" * 20)
    
    # Test each port
    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        try:
            print(f"\nTesting port {port}...")
            result = sock.connect_ex((ip, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                    status = f"Open - {service}"
                except:
                    status = "Open - Unknown service"
            else:
                status = "Closed"
            results.append(f"Port {port}: {status}")
            print(status)
        except socket.error as e:
            results.append(f"Port {port}: Error - {str(e)}")
            print(f"Error scanning port {port}: {str(e)}")
        finally:
            sock.close()
    
    # Save results
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(output_dir, f"port_results_{timestamp}.txt")
    
    with open(output_file, 'w') as f:
        f.write(f"Port Scan Results for {domain}\n")
        f.write("=" * 50 + "\n")
        f.write("\n".join(results))
    
    print(f"\nResults saved to: {output_file}")
    return output_file

if __name__ == "__main__":
    domain = "crypto.com"
    try:
        test_port_scan(domain)
    except KeyboardInterrupt:
        print("\nTest interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)
