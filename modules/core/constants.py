"""Core constants and types for CodesHacks."""

from typing import Dict, List, Union, TypedDict

# Tool information
TOOL_INFO: Dict[str, str] = {
    'name': 'CodesHacks',
    'version': '1.1.0',
    'author': 'Raj Shrivastav',
    'description': 'Advanced Web Reconnaissance & Vulnerability Scanning Tool',
    'repository': 'https://github.com/RAJSHRIVASTAV397/CodesHacks',
    'license': 'MIT'
}

# Default scan modes
SCAN_MODES: List[str] = ['passive', 'active', 'vuln', 'full', 'quick', 'stealth']

# Default ports to scan
DEFAULT_PORTS: List[int] = [
    20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 
    993, 995, 3306, 3389, 5432, 8080, 8443
]

# Common web paths to check
COMMON_PATHS: List[str] = [
    'admin', 'wp-admin', 'administrator', 'login', 'wp-login.php',
    'backup', 'backups', 'data', 'db', 'database', 'dev', 'development',
    'staging', 'test', 'testing', 'api', 'v1', 'v2', 'v3', 'beta'
]

# Common subdomains to check
COMMON_SUBDOMAINS: List[str] = [
    'www', 'mail', 'webmail', 'ftp', 'smtp', 'pop', 'pop3', 'imap',
    'admin', 'administrator', 'blog', 'dev', 'development',
    'stage', 'staging', 'prod', 'production', 'test', 'testing'
]

# Default directories to create
DEFAULT_DIRS: Dict[str, List[str]] = {
    'results': ['recon', 'scan', 'vulnerabilities'],
    'evidence': ['screenshots', 'payloads', 'responses'],
    'logs': ['debug', 'errors', 'requests'],
    'reports': ['json', 'html', 'txt']
}

# Type definitions
class ScanResult(TypedDict):
    """Type definition for scan results."""
    status: str
    findings: List[str]
    errors: List[str]
    duration: float

class VulnFinding(TypedDict):
    """Type definition for vulnerability findings."""
    severity: str
    title: str
    description: str
    evidence: str
    references: List[str]

class PortInfo(TypedDict):
    """Type definition for port scan results."""
    port: int
    protocol: str
    state: str
    service: str
    version: str
