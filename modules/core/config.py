"""Core configuration and setup module for CodesHacks."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

@dataclass
class ToolConfig:
    """Configuration settings for tools."""
    threads: int = 10
    timeout: int = 10
    rate_limit: int = 50
    debug: bool = False
    output_dir: str = "results"
    api_keys: Dict[str, str] = field(default_factory=dict)

@dataclass
class ScanConfig:
    """Configuration settings for scanning."""
    top_ports: int = 1000
    screenshot_timeout: int = 10
    crawl_depth: int = 3
    passive_only: bool = False
    active_only: bool = False
    vuln_only: bool = False
    custom_wordlists: Dict[str, str] = field(default_factory=dict)

class Config:
    """Main configuration class for CodesHacks."""
    
    def __init__(self, config_file: Optional[str] = None):
        """Initialize configuration.
        
        Args:
            config_file: Optional path to configuration file
        """
        self.config_file = config_file or 'codeshacks.ini'
        self.tool_config = ToolConfig()
        self.scan_config = ScanConfig()
        self.logger = self._setup_logging()
        
        if os.path.exists(self.config_file):
            self._load_config()
        else:
            self.logger.warning(f"Config file {self.config_file} not found, using defaults")
    
    def _setup_logging(self) -> logging.Logger:
        """Set up logging configuration.
        
        Returns:
            Logger instance
        """
        logger = logging.getLogger('CodesHacks')
        logger.setLevel(logging.DEBUG)
        
        # Console handler
        console = logging.StreamHandler()
        console.setLevel(logging.INFO)
        console.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
        logger.addHandler(console)
        
        # File handler
        try:
            log_dir = "logs"
            os.makedirs(log_dir, exist_ok=True)
            file_handler = logging.FileHandler(os.path.join(log_dir, 'codeshacks.log'))
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(
                logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            )
            logger.addHandler(file_handler)
        except OSError as e:
            logger.error(f"Failed to set up file logging: {e}")
        
        return logger
    
    def _load_config(self) -> None:
        """Load configuration from file."""
        try:
            import configparser
            config = configparser.ConfigParser()
            config.read(self.config_file)
            
            # Load tool config
            if 'TOOL' in config:
                self.tool_config.threads = config['TOOL'].getint('threads', 10)
                self.tool_config.timeout = config['TOOL'].getint('timeout', 10)
                self.tool_config.rate_limit = config['TOOL'].getint('rate_limit', 50)
                self.tool_config.debug = config['TOOL'].getboolean('debug', False)
                self.tool_config.output_dir = config['TOOL'].get('output_dir', 'results')
            
            # Load scan config
            if 'SCAN' in config:
                self.scan_config.top_ports = config['SCAN'].getint('top_ports', 1000)
                self.scan_config.screenshot_timeout = config['SCAN'].getint('screenshot_timeout', 10)
                self.scan_config.crawl_depth = config['SCAN'].getint('crawl_depth', 3)
                self.scan_config.passive_only = config['SCAN'].getboolean('passive_only', False)
                self.scan_config.active_only = config['SCAN'].getboolean('active_only', False)
                self.scan_config.vuln_only = config['SCAN'].getboolean('vuln_only', False)
            
            # Load API keys
            if 'API_KEYS' in config:
                self.tool_config.api_keys = dict(config['API_KEYS'])
            
            # Load custom wordlists
            if 'WORDLISTS' in config:
                self.scan_config.custom_wordlists = dict(config['WORDLISTS'])
            
            self.logger.info("Configuration loaded successfully")
            
        except Exception as e:
            self.logger.error(f"Error loading configuration: {e}")
            raise
