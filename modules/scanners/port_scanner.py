"""Port scanner module for service detection and analysis."""

import socket
import nmap
from typing import Dict, List, Optional, Any
import concurrent.futures
from dataclasses import dataclass

from .base import BaseScanner
from ..core.exceptions import ScanError
from ..core.constants import DEFAULT_PORTS, PortInfo

@dataclass
class PortScanResult:
    """Container for port scan results."""
    host: str
    port: int
    protocol: str = 'tcp'
    state: str = 'unknown'
    service: str = ''
    version: str = ''

class PortScanner(BaseScanner):
    """Scanner for port and service detection."""
    
    def __init__(self, *args, **kwargs):
        """Initialize port scanner."""
        super().__init__(*args, **kwargs)
        self.nm = nmap.PortScanner()
    
    async def scan(self, target: str, **kwargs: Any) -> Dict:
        """Perform port scan on target.
        
        Args:
            target: Target to scan
            **kwargs: Additional scan parameters
                ports: List of ports to scan
                protocol: Protocol to scan (tcp/udp)
                
        Returns:
            ScanResult containing findings
            
        Raises:
            ScanError: If scan fails
        """
        self.validate_target(target)
        result = self._create_scan_result()
        
        try:
            # Get scan parameters
            ports = kwargs.get('ports', DEFAULT_PORTS)
            protocol = kwargs.get('protocol', 'tcp')
            
            # Perform basic socket scan first
            socket_results = await self._socket_scan(target, ports)
            result['findings'].extend(
                f"Port {r.port}/{r.protocol} is {r.state}" 
                for r in socket_results if r.state == 'open'
            )
            
            # Use nmap for service detection on open ports
            open_ports = [r.port for r in socket_results if r.state == 'open']
            if open_ports:
                nmap_results = await self._nmap_scan(target, open_ports)
                result['findings'].extend(
                    f"Port {r.port}/{r.protocol} {r.service} {r.version}"
                    for r in nmap_results
                )
            
            result['status'] = 'completed'
            return result
            
        except Exception as e:
            error_msg = f"Port scan failed: {str(e)}"
            self.logger.error(error_msg)
            result['status'] = 'error'
            result['errors'].append(error_msg)
            raise ScanError(error_msg)
    
    async def _socket_scan(self, target: str, ports: List[int]) -> List[PortScanResult]:
        """Perform basic TCP connect scan.
        
        Args:
            target: Target to scan
            ports: List of ports to scan
            
        Returns:
            List of PortScanResult
        """
        results = []
        
        def check_port(port: int) -> PortScanResult:
            result = PortScanResult(host=target, port=port)
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.config.tool_config.timeout)
                if sock.connect_ex((target, port)) == 0:
                    result.state = 'open'
                    try:
                        result.service = socket.getservbyport(port)
                    except:
                        pass
                else:
                    result.state = 'closed'
            except:
                result.state = 'error'
            finally:
                sock.close()
            return result
        
        # Use thread pool for parallel scanning
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.config.tool_config.threads
        ) as executor:
            futures = [executor.submit(check_port, port) for port in ports]
            results = [f.result() for f in futures]
        
        return results
    
    async def _nmap_scan(self, target: str, ports: List[int]) -> List[PortScanResult]:
        """Perform detailed scan using nmap.
        
        Args:
            target: Target to scan
            ports: List of ports to scan
            
        Returns:
            List of PortScanResult
        """
        results = []
        try:
            # Convert ports to nmap format
            port_str = ','.join(map(str, ports))
            
            # Run nmap scan
            self.nm.scan(
                target,
                arguments=f'-sV -p{port_str} -T4'
            )
            
            # Parse results
            if target in self.nm.all_hosts():
                for proto in self.nm[target].all_protocols():
                    ports = self.nm[target][proto].keys()
                    for port in ports:
                        port_info = self.nm[target][proto][port]
                        if port_info['state'] == 'open':
                            results.append(PortScanResult(
                                host=target,
                                port=port,
                                protocol=proto,
                                state='open',
                                service=port_info.get('name', ''),
                                version=port_info.get('version', '')
                            ))
        except Exception as e:
            self.logger.error(f"Nmap scan failed: {e}")
            
        return results
