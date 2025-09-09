"""Configuration management for CodesHacks tools."""

import os
import json
import logging
from typing import Dict, Any, Optional
from pathlib import Path

class ConfigManager:
    """Manages tool configurations and settings."""
    
    def __init__(self, config_dir: str = "config", logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
        self.config_dir = config_dir
        self.config_file = os.path.join(config_dir, "tools_config.json")
        self.default_config = {
            "tools": {
                "nuclei": {
                    "templates": ["cves", "vulnerabilities", "misconfiguration"],
                    "severity": ["critical", "high", "medium"],
                    "rate_limit": 150,
                    "timeout": 5,
                    "retries": 3
                },
                "subfinder": {
                    "recursive": True,
                    "timeout": 30,
                    "max_enumerations": 100
                },
                "nmap": {
                    "timing": 4,
                    "top_ports": 1000,
                    "scripts": ["vuln", "default", "discovery"]
                },
                "sqlmap": {
                    "risk": 1,
                    "level": 1,
                    "threads": 4,
                    "timeout": 30,
                    "retries": 3,
                    "batch": True
                },
                "wpscan": {
                    "detection_mode": "aggressive",
                    "plugins_detection": "passive",
                    "themes_detection": "passive",
                    "timthumbs": True,
                    "config_backups": True
                },
                "burpsuite": {
                    "scan_speed": "fast",
                    "scope": "strict",
                    "audit_checks": ["active", "passive"],
                    "crawl_strategy": "detailed"
                },
                "metasploit": {
                    "workspace": "default",
                    "lhost": "0.0.0.0",
                    "lport": 4444,
                    "payload_type": "reverse_tcp"
                },
                "mobsf": {
                    "scan_type": "all",
                    "export_format": "pdf",
                    "api_only": False
                },
                "trivy": {
                    "severity": ["CRITICAL", "HIGH"],
                    "vuln_type": ["os", "library"],
                    "ignore_unfixed": True
                }
            },
            "general": {
                "output_dir": "results",
                "max_threads": 10,
                "debug": False,
                "auto_update": True,
                "proxy": None,
                "user_agent": "CodesHacks Security Scanner"
            },
            "api_keys": {
                "shodan": "",
                "censys": "",
                "virustotal": "",
                "securitytrails": "",
                "wpscan": "",
                "github": ""
            }
        }
        
        self.config = self.load_config()
    
    def load_config(self) -> Dict[str, Any]:
        """Load configuration from file or create default."""
        try:
            if not os.path.exists(self.config_dir):
                os.makedirs(self.config_dir)
            
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    # Merge with default config to ensure all keys exist
                    return self._merge_configs(self.default_config, config)
            else:
                # Create default config file
                self.save_config(self.default_config)
                return self.default_config
                
        except Exception as e:
            self.logger.error(f"Error loading config: {str(e)}")
            return self.default_config
    
    def save_config(self, config: Dict[str, Any]) -> bool:
        """Save configuration to file."""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=4)
            return True
        except Exception as e:
            self.logger.error(f"Error saving config: {str(e)}")
            return False
    
    def get_tool_config(self, tool_name: str) -> Dict[str, Any]:
        """Get configuration for specific tool."""
        return self.config['tools'].get(tool_name, {})
    
    def update_tool_config(self, tool_name: str, new_config: Dict[str, Any]) -> bool:
        """Update configuration for specific tool."""
        try:
            if tool_name not in self.config['tools']:
                self.config['tools'][tool_name] = {}
            self.config['tools'][tool_name].update(new_config)
            return self.save_config(self.config)
        except Exception as e:
            self.logger.error(f"Error updating tool config: {str(e)}")
            return False
    
    def set_api_key(self, service: str, key: str) -> bool:
        """Set API key for a service."""
        try:
            self.config['api_keys'][service] = key
            return self.save_config(self.config)
        except Exception as e:
            self.logger.error(f"Error setting API key: {str(e)}")
            return False
    
    def get_api_key(self, service: str) -> Optional[str]:
        """Get API key for a service."""
        return self.config['api_keys'].get(service)
    
    def update_general_config(self, new_config: Dict[str, Any]) -> bool:
        """Update general configuration settings."""
        try:
            self.config['general'].update(new_config)
            return self.save_config(self.config)
        except Exception as e:
            self.logger.error(f"Error updating general config: {str(e)}")
            return False
    
    def _merge_configs(self, default: Dict[str, Any], user: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively merge user config with default config."""
        merged = default.copy()
        
        for key, value in user.items():
            if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
                merged[key] = self._merge_configs(merged[key], value)
            else:
                merged[key] = value
                
        return merged
    
    def export_config(self, export_path: str) -> bool:
        """Export configuration to a file."""
        try:
            with open(export_path, 'w') as f:
                json.dump(self.config, f, indent=4)
            return True
        except Exception as e:
            self.logger.error(f"Error exporting config: {str(e)}")
            return False
    
    def import_config(self, import_path: str) -> bool:
        """Import configuration from a file."""
        try:
            with open(import_path, 'r') as f:
                new_config = json.load(f)
            self.config = self._merge_configs(self.default_config, new_config)
            return self.save_config(self.config)
        except Exception as e:
            self.logger.error(f"Error importing config: {str(e)}")
            return False
    
    def reset_tool_config(self, tool_name: str) -> bool:
        """Reset tool configuration to default."""
        try:
            if tool_name in self.default_config['tools']:
                self.config['tools'][tool_name] = self.default_config['tools'][tool_name].copy()
                return self.save_config(self.config)
            return False
        except Exception as e:
            self.logger.error(f"Error resetting tool config: {str(e)}")
            return False
    
    def reset_all_config(self) -> bool:
        """Reset all configurations to default."""
        try:
            self.config = self.default_config.copy()
            return self.save_config(self.config)
        except Exception as e:
            self.logger.error(f"Error resetting all config: {str(e)}")
            return False
