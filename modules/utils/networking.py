"""Utility functions for network operations."""

import socket
import ssl
import asyncio
from typing import Optional, Tuple, List, Dict
import aiohttp
import dns.resolver
import dns.exception

async def resolve_dns(domain: str, record_type: str = 'A') -> List[str]:
    """Resolve DNS records for a domain.
    
    Args:
        domain: Domain name to resolve
        record_type: DNS record type (A, AAAA, MX, etc.)
        
    Returns:
        List of resolved records
        
    Raises:
        dns.exception.DNSException: If DNS resolution fails
    """
    try:
        answers = dns.resolver.resolve(domain, record_type)
        return [str(rdata) for rdata in answers]
    except dns.exception.DNSException as e:
        raise e

async def check_port(host: str, port: int, timeout: float = 2.0) -> Tuple[bool, Optional[str]]:
    """Check if a port is open on a host.
    
    Args:
        host: Target hostname or IP
        port: Port number to check
        timeout: Connection timeout in seconds
        
    Returns:
        Tuple of (is_open, banner)
    """
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )
        banner = await writer.read(1024)
        writer.close()
        await writer.wait_closed()
        return True, banner.decode('utf-8', errors='ignore')
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return False, None

async def make_http_request(url: str, 
                          method: str = 'GET',
                          headers: Optional[Dict[str, str]] = None,
                          data: Optional[Dict] = None,
                          verify_ssl: bool = True,
                          timeout: float = 10.0) -> Tuple[int, Dict[str, str], bytes]:
    """Make an HTTP request.
    
    Args:
        url: Target URL
        method: HTTP method
        headers: Request headers
        data: Request data/params
        verify_ssl: Verify SSL certificates
        timeout: Request timeout in seconds
        
    Returns:
        Tuple of (status_code, headers, content)
        
    Raises:
        aiohttp.ClientError: If request fails
    """
    async with aiohttp.ClientSession() as session:
        async with session.request(
            method=method,
            url=url,
            headers=headers,
            data=data,
            verify_ssl=verify_ssl,
            timeout=aiohttp.ClientTimeout(total=timeout)
        ) as response:
            content = await response.read()
            return (
                response.status,
                dict(response.headers),
                content
            )

def get_ssl_info(hostname: str, port: int = 443) -> Dict[str, str]:
    """Get SSL certificate information for a host.
    
    Args:
        hostname: Target hostname
        port: SSL port number
        
    Returns:
        Dictionary of certificate information
        
    Raises:
        ssl.SSLError: If SSL connection fails
        socket.error: If connection fails
    """
    context = ssl.create_default_context()
    with socket.create_connection((hostname, port)) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()
            
            return {
                'subject': dict(x[0] for x in cert['subject']),
                'issuer': dict(x[0] for x in cert['issuer']),
                'version': cert['version'],
                'serialNumber': cert['serialNumber'],
                'notBefore': cert['notBefore'],
                'notAfter': cert['notAfter'],
                'subjectAltName': [x[1] for x in cert['subjectAltName']],
                'OCSP': cert.get('OCSP', []),
                'caIssuers': cert.get('caIssuers', []),
                'crlDistributionPoints': cert.get('crlDistributionPoints', [])
            }
