#!/usr/bin/env python3

import os
import logging
from scanner import Scanner

def main():
    # Setup logging
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('test_scan.log')
        ]
    )
    logger = logging.getLogger('CodesHacks')
    logger.setLevel(logging.DEBUG)

    # Configuration
    config = {
        'api_keys': {
            'shodan': 'IRqdDbM9QtbdHqAfbIDAxZceyqKAvejk',
        },
        'threads': 5,
        'timeout': 10,
        'rate_limit': 10,
        'output_dir': 'results'
    }

    # Create scanner
    scanner = Scanner(config, logger)

    # Target domain
    target = "crypto.com"

    # Create output directory
    os.makedirs('results', exist_ok=True)
    session_dir = os.path.join('results', 'test_scan')
    os.makedirs(session_dir, exist_ok=True)

    try:
        # 1. DNS Enumeration
        logger.info("\n=== Starting DNS Enumeration ===")
        subs_file = scanner.passive_recon(target, session_dir)
        logger.info(f"DNS enumeration results saved to: {subs_file}")

        # 2. Port Scanning
        logger.info("\n=== Starting Port Scanning ===")
        ports_file = os.path.join(session_dir, "ports.txt")
        scanner.scan_ports(subs_file, ports_file)
        logger.info(f"Port scanning results saved to: {ports_file}")

        # 3. Web Analysis
        logger.info("\n=== Starting Web Analysis ===")
        web_file = os.path.join(session_dir, "web.txt")
        scanner.analyze_web_server(target, web_file)
        logger.info(f"Web analysis results saved to: {web_file}")

    except KeyboardInterrupt:
        logger.warning("\nScan interrupted by user")
    except Exception as e:
        logger.error(f"Error during scan: {str(e)}", exc_info=True)

if __name__ == "__main__":
    main()
