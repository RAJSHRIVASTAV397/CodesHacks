"""Utility functions for logging and messages."""

import logging
import sys
from typing import Optional
from datetime import datetime

# ANSI escape codes for colors
COLORS = {
    'red': '\033[91m',
    'green': '\033[92m',
    'yellow': '\033[93m',
    'blue': '\033[94m',
    'magenta': '\033[95m',
    'cyan': '\033[96m',
    'white': '\033[97m',
    'reset': '\033[0m'
}

def setup_logging(log_file: Optional[str] = None, debug: bool = False) -> logging.Logger:
    """Configure logging for the application.
    
    Args:
        log_file: Optional path to log file
        debug: Enable debug logging
        
    Returns:
        Configured logger instance
    """
    # Create logger
    logger = logging.getLogger('codeshacks')
    logger.setLevel(logging.DEBUG if debug else logging.INFO)
    
    # Create formatters
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    console_formatter = logging.Formatter(
        '%(message)s'
    )
    
    # Setup console handler
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(console_formatter)
    console.setLevel(logging.DEBUG if debug else logging.INFO)
    logger.addHandler(console)
    
    # Setup file handler if log file specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(file_formatter)
        file_handler.setLevel(logging.DEBUG)
        logger.addHandler(file_handler)
    
    return logger

def print_banner() -> None:
    """Print the application banner."""
    banner = """
    ██████╗ ██████╗ ██████╗ ███████╗███████╗██╗  ██╗ █████╗  ██████╗██╗  ██╗███████╗
    ██╔════╝██╔═══██╗██╔══██╗██╔════╝██╔════╝██║  ██║██╔══██╗██╔════╝██║ ██╔╝██╔════╝
    ██║     ██║   ██║██║  ██║█████╗  ███████╗███████║███████║██║     █████╔╝ ███████╗
    ██║     ██║   ██║██║  ██║██╔══╝  ╚════██║██╔══██║██╔══██║██║     ██╔═██╗ ╚════██║
    ╚██████╗╚██████╔╝██████╔╝███████╗███████║██║  ██║██║  ██║╚██████╗██║  ██╗███████║
    ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝
    """
    print(f"{COLORS['cyan']}{banner}{COLORS['reset']}")
    print(f"{COLORS['yellow']}{'=' * 80}{COLORS['reset']}\n")

def colored_text(text: str, color: str) -> str:
    """Add color to console text.
    
    Args:
        text: Text to colorize
        color: Color name from COLORS dict
        
    Returns:
        Colorized text string
    """
    if color not in COLORS:
        return text
    return f"{COLORS[color]}{text}{COLORS['reset']}"

def print_status(message: str, status: str = 'info') -> None:
    """Print a status message with appropriate color.
    
    Args:
        message: Message to print
        status: Status type (info, success, warning, error)
    """
    color_map = {
        'info': 'white',
        'success': 'green',
        'warning': 'yellow',
        'error': 'red'
    }
    color = color_map.get(status, 'white')
    print(colored_text(message, color))
