#!/usr/bin/env python3

"""
CodesHacks CLI - Command Line Interface for the Security Assessment Framework
"""

import argparse
import logging
import os
import sys
import json
from modules.scanner import Scanner

def setup_logging(log_level=logging.INFO):
    """Configure logging for the application"""
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        force=True
    )
    logger = logging.getLogger('CodesHacks')
    logger.setLevel(log_level)
    return logger

def load_config(config_file=None):
    """Load configuration from file or use defaults"""
    default_config = {
        'threads': 10,
        'timeout': 300,
        'rate_limit': 50,
        'output': {
            'directory': 'results',
            'format': ['txt', 'json'],
            'verbosity': 'info'
        },
        'wordlists': {
            'directories': 'wordlists/directories.txt',
            'subdomains': 'wordlists/subdomains.txt'
        },
        'tools': {
            'nmap': True,
            'nikto': True,
            'sqlmap': True,
            'wpscan': True,
            'gobuster': True,
            'sslyze': True,
            'nuclei': True,
            'whatweb': True,
            'droopescan': True,
            'skipfish': True,
            'arachni': True
        }
    }

    try:
        if config_file and os.path.exists(config_file):
            print(f"Loading config from: {config_file}")
            with open(config_file) as f:
                user_config = json.load(f)
                print(f"User config: {json.dumps(user_config, indent=2)}")
                default_config.update(user_config)
                print(f"Final config: {json.dumps(default_config, indent=2)}")
    except Exception as e:
        print(f"Error loading config file: {e}")
        raise

    return default_config

    def load_config(config_file=None):
        """Load configuration from file or use defaults"""
        default_config = {
            'threads': 10,
            'timeout': 300,
            'rate_limit': 50,
            'output': {
                'directory': 'results',
                'format': ['txt', 'json'],
                'verbosity': 'info'
            },
            'wordlists': {
                'directories': '/usr/share/wordlists/dirb/big.txt',
                'subdomains': '/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt'
            },
            'tools': {
                'nmap': True,
                'nikto': True,
                'sqlmap': True,
                'wpscan': True,
                'gobuster': True,
                'sslyze': True,
                'nuclei': True,
                'whatweb': True,
                'droopescan': True,
                'skipfish': True,
                'arachni': True
            }
        }

        if config_file and os.path.exists(config_file):
            try:
                print(f"Loading config from: {config_file}")
                with open(config_file) as f:
                    user_config = json.load(f)
                    print(f"User config: {json.dumps(user_config, indent=2)}")
                    default_config.update(user_config)
            except Exception as e:
                print(f"Error loading config file: {e}")
                sys.exit(1)

        print(f"Final config: {json.dumps(default_config, indent=2)}")
        return default_config

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="CodesHacks - Advanced Security Assessment Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    scan_type = parser.add_mutually_exclusive_group(required=True)
    scan_type.add_argument('-q', '--quick', action='store_true',
                          help='Perform a quick scan')
    scan_type.add_argument('-f', '--full', action='store_true',
                          help='Perform a full comprehensive scan')
    scan_type.add_argument('-c', '--custom', metavar='DOMAIN',
                          help='Perform a custom scan on specified domain')

    parser.add_argument('-t', '--threads', type=int, default=10,
                       help='Number of concurrent threads')
    parser.add_argument('-w', '--wordlist',
                       help='Custom wordlist for directory scanning')
    parser.add_argument('-o', '--output', help='Output directory for scan results')
    parser.add_argument('--timeout', type=int, default=300,
                       help='Timeout for individual scans in seconds')
    parser.add_argument('--rate-limit', type=int, default=50,
                       help='Maximum requests per second')
    
    # Advanced options
    advanced = parser.add_argument_group('Advanced Options')
    advanced.add_argument('--proxy', help='Proxy URL (e.g., http://proxy:8080)')
    advanced.add_argument('--cookies', help='File containing cookies')
    advanced.add_argument('--user-agent', help='Custom User-Agent string')
    advanced.add_argument('--follow-redirects', action='store_true',
                         help='Follow redirects in requests')
    advanced.add_argument('--max-depth', type=int, default=3,
                         help='Maximum directory depth to scan')
    advanced.add_argument('--exclude', help='Skip paths matching pattern')
    advanced.add_argument('--include', help='Only scan paths matching pattern')
    
    # Tool selection for custom scan
    tools = parser.add_argument_group('Tool Selection (for custom scan)')
    tools.add_argument('--tools', help='Comma-separated list of tools to use')
    
    # Logging options
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('-d', '--debug', action='store_true',
                       help='Enable debug logging')
    parser.add_argument('--config', help='Path to configuration file')

    return parser.parse_args()

def main():
    """Main entry point for the CLI"""
    try:
        # Parse arguments
        args = parse_args()
        print("Arguments parsed:", vars(args))
        
        # Setup logging with custom name
        logger_name = 'CodesHacks'
        log_level = logging.DEBUG if args.debug else (
            logging.INFO if args.verbose else logging.WARNING
        )
        logger = setup_logging(log_level)
        print("Logger created with level:", log_level)
        logger.info("=" * 60)
        logger.info("Starting CodesHacks Security Scanner")
        logger.info("=" * 60)
        
        # Log arguments
        logger.debug("Command line arguments:")
        for arg, value in vars(args).items():
            logger.debug(f"  {arg}: {value}")
        
        # Load configuration
        try:
            config = load_config(args.config)
            logger.debug("Base configuration loaded successfully")
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            raise
            
        # Override config with command line arguments
        try:
            config.update({
                'threads': args.threads,
                'timeout': args.timeout,
                'rate_limit': args.rate_limit,
                'output': {
                    'directory': args.output or config.get('output', {}).get('directory', 'results'),
                    'format': config.get('output', {}).get('format', ['txt']),
                    'verbosity': 'debug' if args.debug else 'info'
                },
                'proxy': args.proxy,
                'cookies': args.cookies,
                'user_agent': args.user_agent,
                'follow_redirects': args.follow_redirects,
                'max_depth': args.max_depth,
                'exclude_pattern': args.exclude,
                'include_pattern': args.include
            })
            logger.debug("Configuration updated with command line arguments")
        except Exception as e:
            logger.error(f"Error updating configuration: {e}")
            raise

        # Log final configuration
        logger.debug("Final configuration:")
        for key, value in config.items():
            logger.debug(f"  {key}: {value}")

        if args.wordlist:
            config['wordlists'] = config.get('wordlists', {})
            config['wordlists']['directories'] = args.wordlist
            logger.debug(f"Custom wordlist configured: {args.wordlist}")

        # Initialize scanner
        try:
            logger.info("Initializing scanner...")
            scanner = Scanner(config, logger)
            logger.info("Scanner initialized successfully")
        except Exception as e:
            logger.error(f"Error initializing scanner: {e}")
            raise
        
        try:
            # Determine target and scan type
            target = args.custom if args.custom else args.target
            logger.info(f"Target: {target}")
            
            # Execute scan based on type
            if args.quick:
                logger.info("Starting quick scan...")
                result = scanner.quick_scan(target)
            elif args.full:
                logger.info("Starting full comprehensive scan...")
                result = scanner.full_scan(target)
            else:  # custom scan
                if not args.tools:
                    logger.error("Custom scan requires --tools argument")
                    sys.exit(1)
                tools = [t.strip() for t in args.tools.split(',')]
                logger.info(f"Starting custom scan with tools: {', '.join(tools)}...")
                result = scanner.custom_scan(target, tools)

            logger.info("=" * 60)
            logger.info(f"Scan completed successfully")
            logger.info(f"Results saved to: {result}")
            logger.info("=" * 60)

        except KeyboardInterrupt:
            logger.warning("\nScan interrupted by user")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Error during scan execution: {str(e)}")
            if args.debug:
                logger.debug("Full stack trace:", exc_info=True)
            raise

    except Exception as e:
        logger.error(f"Critical error: {str(e)}")
        if args.debug:
            import traceback
            logger.debug("Full stack trace:")
            logger.debug(traceback.format_exc())
        sys.exit(1)

    finally:
        logger.info("Scanner shutdown complete")

if __name__ == '__main__':
    main()
