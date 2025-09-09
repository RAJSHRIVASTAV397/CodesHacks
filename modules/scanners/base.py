"""Base scanner module providing common scanning functionality."""

import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from ..core.config import Config
from ..core.exceptions import ScanError
from ..core.constants import ScanResult

class BaseScanner(ABC):
    """Abstract base class for all scanners."""
    
    def __init__(self, config: Config, logger: Optional[logging.Logger] = None):
        """Initialize scanner with configuration.
        
        Args:
            config: Tool configuration
            logger: Optional logger instance
        """
        self.config = config
        self.logger = logger or logging.getLogger(__name__)
        self._validate_config()
    
    def _validate_config(self) -> None:
        """Validate scanner configuration."""
        if not self.config:
            raise ScanError("Scanner configuration is required")
    
    @abstractmethod
    def scan(self, target: str, **kwargs: Any) -> ScanResult:
        """Perform scan on target.
        
        Args:
            target: Target to scan
            **kwargs: Additional scan parameters
            
        Returns:
            ScanResult containing findings
            
        Raises:
            ScanError: If scan fails
        """
        pass
    
    def _create_scan_result(self) -> ScanResult:
        """Create empty scan result."""
        return {
            'status': 'initialized',
            'findings': [],
            'errors': [],
            'duration': 0.0
        }
    
    def validate_target(self, target: str) -> None:
        """Validate scan target.
        
        Args:
            target: Target to validate
            
        Raises:
            ValueError: If target is invalid
        """
        if not target:
            raise ValueError("Target is required")
        # Add more validation as needed
