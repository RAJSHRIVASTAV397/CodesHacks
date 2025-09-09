import dns.resolver
import logging

class DNSScanner:
    def __init__(self, logger=None):
        self.logger = logger or logging.getLogger(__name__)
        self.nameservers = ['8.8.8.8', '1.1.1.1', '8.8.4.4']
        
    def scan(self, domain, output_file):
        """Perform comprehensive DNS enumeration"""
        self.logger.info(f"Starting DNS enumeration for {domain}")
        
        with open(output_file, 'w') as f:
            f.write(f"DNS Records for {domain}\n")
            f.write("=" * 50 + "\n\n")
            
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            resolver.lifetime = 3
            
            for ns in self.nameservers:
                resolver.nameservers = [ns]
                f.write(f"\nUsing nameserver: {ns}\n")
                
                for record in record_types:
                    try:
                        f.write(f"\n{record} Records:\n")
                        f.write("-" * 20 + "\n")
                        answers = resolver.resolve(domain, record)
                        for rdata in answers:
                            f.write(f"{str(rdata)}\n")
                        break  # If successful, move to next record type
                    except dns.resolver.NoAnswer:
                        f.write(f"No {record} records found\n")
                    except dns.resolver.NXDOMAIN:
                        f.write(f"Domain does not exist\n")
                        break
                    except dns.resolver.Timeout:
                        f.write(f"Timeout querying {record} records\n")
                    except Exception as e:
                        f.write(f"Error: {str(e)}\n")
        
        self.logger.info(f"DNS enumeration completed. Results saved to {output_file}")
        return output_file
