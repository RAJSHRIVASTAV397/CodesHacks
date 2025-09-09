#!/usr/bin/env python3

import os
import sys
import dns.resolver
import requests
from datetime import datetime

def test_dns_enum(domain):
    """Test DNS enumeration on a domain"""
    print(f"\nTesting DNS enumeration for {domain}")
    
    # Create output directory
    output_dir = "dns_test_results"
    os.makedirs(output_dir, exist_ok=True)
    
    results = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5
    
    # Common DNS record types to check
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT']
    
    for record_type in record_types:
        try:
            print(f"\nChecking {record_type} records...")
            answers = resolver.resolve(domain, record_type)
            results.append(f"\n{record_type} Records:")
            for rdata in answers:
                results.append(f"  {str(rdata)}")
                print(f"Found: {str(rdata)}")
        except dns.resolver.NoAnswer:
            results.append(f"\n{record_type} Records: No records found")
            print(f"No {record_type} records found")
        except dns.resolver.NXDOMAIN:
            results.append(f"\n{record_type} Records: Domain does not exist")
            print(f"Domain does not exist")
        except Exception as e:
            results.append(f"\n{record_type} Records: Error - {str(e)}")
            print(f"Error checking {record_type} records: {str(e)}")
    
    # Save results
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(output_dir, f"dns_results_{timestamp}.txt")
    
    with open(output_file, 'w') as f:
        f.write(f"DNS Enumeration Results for {domain}\n")
        f.write("=" * 50 + "\n")
        f.write("\n".join(results))
    
    print(f"\nResults saved to: {output_file}")
    return output_file

if __name__ == "__main__":
    domain = "crypto.com"
    try:
        test_dns_enum(domain)
    except KeyboardInterrupt:
        print("\nTest interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)
