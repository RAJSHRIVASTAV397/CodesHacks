import socket
import logging
from concurrent.futures import ThreadPoolExecutor

class PortScanner:
    def __init__(self, logger=None):
        self.logger = logger or logging.getLogger(__name__)
        self.common_ports = [
            80, 443, 8080, 8443,  # Web
            21, 22, 23,           # FTP, SSH, Telnet
            25, 587, 465,         # Email
            53,                   # DNS
            3306, 5432,          # Databases
            2082, 2083, 2086, 2087  # cPanel
        ]
        
    def check_port(self, ip, port):
        """Check if a specific port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"
                return port, True, service
            return port, False, None
        except:
            return port, False, None
    
    def scan(self, target, output_file):
        """Perform port scanning with parallel execution"""
        self.logger.info(f"Starting port scan for {target}")
        
        with open(output_file, 'w') as f:
            f.write(f"Port Scan Results for {target}\n")
            f.write("=" * 50 + "\n\n")
            
            try:
                # Get IP address(es)
                # Try to get IPs using dns.resolver first
                try:
                    import dns.resolver
                    resolver = dns.resolver.Resolver()
                    resolver.timeout = 3
                    answers = resolver.resolve(target, 'A')
                    ips = [str(rdata) for rdata in answers]
                    f.write("IP Addresses:\n")
                    for ip in ips:
                        f.write(f"{ip}\n")
                except Exception:
                    # Fallback to socket if dns.resolver fails
                    try:
                        ip = socket.gethostbyname(target)
                        ips = [ip]
                        f.write(f"IP Address: {ip}\n")
                    except socket.gaierror:
                        f.write(f"Could not resolve hostname {target}\n")
                        return output_file
                
                f.write("\nScanning Ports:\n")
                f.write("-" * 20 + "\n")
                
                # Scan ports in parallel
                for ip in ips:
                    with ThreadPoolExecutor(max_workers=10) as executor:
                        future_to_port = {
                            executor.submit(self.check_port, ip, port): port 
                            for port in self.common_ports
                        }
                        for future in future_to_port:
                            port, is_open, service = future.result()
                            if is_open:
                                f.write(f"Port {port}/tcp ({service}) is open\n")
                
            except Exception as e:
                f.write(f"Error during port scan: {str(e)}\n")
        
        self.logger.info(f"Port scan completed. Results saved to {output_file}")
        return output_file
