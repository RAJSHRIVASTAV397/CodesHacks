"""DNS scanner module for domain enumeration and analysis."""

import dns.resolver
import dns.zone
from typing import List, Set, Optional, Any
import asyncio
import aiohttp
from urllib.parse import urlparse

from .base import BaseScanner
from ..core.exceptions import ScanError
from ..core.constants import COMMON_SUBDOMAINS
from ..core.scan_result import ScanResult

class DnsScanner(BaseScanner):
    """Scanner for DNS enumeration and analysis."""
    
    async def scan(self, domain: str, **kwargs: Any) -> ScanResult:
        """Perform DNS enumeration on domain.
        
        Args:
            domain: Target domain
            **kwargs: Additional scan parameters
            
        Returns:
            ScanResult containing findings
            
        Raises:
            ScanError: If scan fails
        """
        self.validate_target(domain)
        result = self._create_scan_result()
        
        try:
            # Basic DNS enumeration
            subdomains = await self._enumerate_subdomains(domain)
            result['findings'].extend(subdomains)
            
            # Try zone transfer
            zone_results = await self._try_zone_transfer(domain)
            if zone_results:
                result['findings'].extend(zone_results)
            
            # Get DNS records
            records = await self._get_dns_records(domain)
            result['findings'].extend(records)
            
            result['status'] = 'completed'
            return result
            
        except Exception as e:
            error_msg = f"DNS scan failed: {str(e)}"
            self.logger.error(error_msg)
            result['status'] = 'error'
            result['errors'].append(error_msg)
            raise ScanError(error_msg)
    
    async def _enumerate_subdomains(self, domain: str) -> Set[str]:
        """Enumerate subdomains using various techniques.
        
        Args:
            domain: Target domain
            
        Returns:
            Set of discovered subdomains
        """
        subdomains: Set[str] = set()
        
        # Try common subdomains
        for sub in COMMON_SUBDOMAINS:
            test_domain = f"{sub}.{domain}"
            try:
                answers = await self._async_resolve(test_domain, 'A')
                if answers:
                    subdomains.add(test_domain)
                    # Also try CNAME
                    cname_answers = await self._async_resolve(test_domain, 'CNAME')
                    if cname_answers:
                        subdomains.add(str(cname_answers[0]).rstrip('.'))
            except:
                continue
        
        return subdomains
    
    async def _try_zone_transfer(self, domain: str) -> List[str]:
        """Attempt DNS zone transfer.
        
        Args:
            domain: Target domain
            
        Returns:
            List of records from zone transfer
        """
        results = []
        try:
            ns_records = await self._async_resolve(domain, 'NS')
            if ns_records:
                for ns in ns_records:
                    try:
                        zone = dns.zone.from_xfr(dns.query.xfr(str(ns), domain))
                        for name, _ in zone.nodes.items():
                            results.append(f"{name}.{domain}")
                    except:
                        continue
        except:
            pass
        return results
    
    async def _get_dns_records(self, domain: str) -> List[str]:
        """Get various DNS records for domain.
        
        Args:
            domain: Target domain
            
        Returns:
            List of DNS records
        """
        records = []
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CAA']
        
        for record_type in record_types:
            try:
                answers = await self._async_resolve(domain, record_type)
                if answers:
                    records.append(f"{record_type} Records:")
                    for rdata in answers:
                        records.append(f"  {str(rdata)}")
            except:
                continue
        
        return records
    
    async def _async_resolve(self, domain: str, record_type: str) -> List[Any]:
        """Asynchronously resolve DNS records.
        
        Args:
            domain: Domain to resolve
            record_type: Type of DNS record
            
        Returns:
            List of DNS answers
        """
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.config.tool_config.timeout
            resolver.lifetime = self.config.tool_config.timeout
            answers = resolver.resolve(domain, record_type)
            return list(answers)
        except:
            return []
