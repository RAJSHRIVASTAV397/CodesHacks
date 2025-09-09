# API Documentation

## Core Classes

### Scanner

The main scanning orchestrator that coordinates different scanning modules.

```python
class Scanner:
    def __init__(self, config: Dict[str, Any], logger: Logger) -> None:
        """Initialize Scanner with configuration.
        
        Args:
            config: Configuration dictionary
            logger: Logger instance
        """
        pass

    async def quick_scan(self, target: str) -> ScanResult:
        """Perform a quick scan of the target.
        
        Args:
            target: Target domain or IP
            
        Returns:
            ScanResult containing findings
        """
        pass

    async def full_scan(self, target: str) -> ScanResult:
        """Perform a comprehensive scan of the target.
        
        Args:
            target: Target domain or IP
            
        Returns:
            ScanResult containing findings
        """
        pass
```

### NetworkScanner

Handles network-level scanning operations.

```python
class NetworkScanner:
    def scan_ports(self, target: str, ports: List[int]) -> List[Port]:
        """Scan specific ports on target.
        
        Args:
            target: Target IP or domain
            ports: List of ports to scan
            
        Returns:
            List of open ports with service information
        """
        pass
```

### WebScanner

Handles web application scanning.

```python
class WebScanner:
    async def scan_vulnerabilities(self, url: str) -> List[Vulnerability]:
        """Scan for web vulnerabilities.
        
        Args:
            url: Target URL
            
        Returns:
            List of found vulnerabilities
        """
        pass
```

## Configuration

### Environment Variables

- `CODESHACKS_CONFIG`: Path to config file
- `CODESHACKS_DEBUG`: Enable debug logging
- `CODESHACKS_API_KEY`: API key for premium features

### Config File Structure

```json
{
    "general": {
        "threads": 10,
        "timeout": 300,
        "rate_limit": 10,
        "user_agent": "CodesHacks/1.0"
    },
    "scanning": {
        "max_depth": 2,
        "exclude_patterns": []
    }
}
```

## Usage Examples

### Basic Scanning

```python
from codeshacks import Scanner

scanner = Scanner(config)
results = await scanner.quick_scan("example.com")
```

### Custom Scan Configuration

```python
config = {
    "general": {
        "threads": 20,
        "timeout": 600
    },
    "scanning": {
        "max_depth": 3
    }
}

scanner = Scanner(config)
results = await scanner.full_scan("example.com")
```

### Working with Results

```python
for vuln in results.vulnerabilities:
    print(f"Found {vuln.severity} vulnerability: {vuln.description}")
```
