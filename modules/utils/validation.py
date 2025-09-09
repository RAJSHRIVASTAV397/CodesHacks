"""Utility functions for validation and data parsing."""

import re
import ipaddress
from typing import Union, List, Dict, Any, Optional
from urllib.parse import urlparse

def is_valid_domain(domain: str) -> bool:
    """Check if a string is a valid domain name.
    
    Args:
        domain: Domain string to check
        
    Returns:
        True if valid domain, False otherwise
    """
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))

def is_valid_ip(ip: str) -> bool:
    """Check if a string is a valid IP address.
    
    Args:
        ip: IP address string to check
        
    Returns:
        True if valid IP, False otherwise
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_valid_port(port: Union[str, int]) -> bool:
    """Check if a port number is valid.
    
    Args:
        port: Port number to check
        
    Returns:
        True if valid port, False otherwise
    """
    try:
        port_num = int(port)
        return 0 <= port_num <= 65535
    except ValueError:
        return False

def is_valid_url(url: str) -> bool:
    """Check if a string is a valid URL.
    
    Args:
        url: URL string to check
        
    Returns:
        True if valid URL, False otherwise
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

def parse_target(target: str) -> Dict[str, Any]:
    """Parse a target string into components.
    
    Args:
        target: Target string (IP, domain, or URL)
        
    Returns:
        Dictionary of parsed components
    """
    result = {
        'type': None,
        'host': None,
        'ip': None,
        'port': None,
        'scheme': None,
        'path': None,
        'query': None
    }
    
    if is_valid_ip(target):
        result['type'] = 'ip'
        result['ip'] = target
        result['host'] = target
    
    elif is_valid_domain(target):
        result['type'] = 'domain'
        result['host'] = target
    
    elif is_valid_url(target):
        result['type'] = 'url'
        parsed = urlparse(target)
        result['scheme'] = parsed.scheme
        result['host'] = parsed.hostname
        result['port'] = parsed.port
        result['path'] = parsed.path
        result['query'] = parsed.query
        
        if is_valid_ip(parsed.hostname):
            result['ip'] = parsed.hostname
    
    return result

def parse_port_range(port_spec: str) -> List[int]:
    """Parse a port specification into a list of ports.
    
    Args:
        port_spec: Port specification (e.g. "80,443" or "8000-8010")
        
    Returns:
        List of port numbers
        
    Raises:
        ValueError: If port specification is invalid
    """
    ports = set()
    
    for item in port_spec.split(','):
        if '-' in item:
            start, end = map(int, item.split('-'))
            if not (is_valid_port(start) and is_valid_port(end)):
                raise ValueError(f"Invalid port range: {item}")
            ports.update(range(start, end + 1))
        else:
            port = int(item)
            if not is_valid_port(port):
                raise ValueError(f"Invalid port: {port}")
            ports.add(port)
    
    return sorted(list(ports))

def normalize_target(target: str) -> str:
    """Normalize a target string.
    
    Args:
        target: Target string to normalize
        
    Returns:
        Normalized target string
    """
    # Remove leading/trailing whitespace
    target = target.strip()
    
    # Remove protocol if present
    if '://' in target:
        target = target.split('://', 1)[1]
    
    # Remove path and query components
    if '/' in target:
        target = target.split('/', 1)[0]
    
    # Remove port specification if present
    if ':' in target:
        target = target.split(':', 1)[0]
    
    return target.lower()
